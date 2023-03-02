package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pyke369/golang-support/acl"
	"github.com/pyke369/golang-support/dynacert"
	j "github.com/pyke369/golang-support/jsonrpc"
	"github.com/pyke369/golang-support/rcache"
)

func serverLoad(prefix string, slot int) (size, created int64, ttl int, tags string) {
	if content, err := os.ReadFile(filepath.Join(prefix, fmt.Sprintf("%02d.meta", slot))); err == nil {
		meta := map[string]any{}
		if json.Unmarshal(content, &meta) == nil {
			size, created, ttl, tags = int64(j.Number(meta["size"])), int64(j.Number(meta["created"])), int(j.Number(meta["ttl"])), j.String(meta["tags"])
			if info, err := os.Stat(filepath.Join(prefix, fmt.Sprintf("%02d", slot))); err != nil || info.Size() != size || info.ModTime().Unix() != created {
				size, created, ttl = 0, 0, 0
			}
		}
	}
	return
}
func serverSave(prefix string, slot int, size, created int64, ttl int, tags string) {
	if size <= 0 || created <= 0 {
		if info, err := os.Stat(filepath.Join(prefix, fmt.Sprintf("%02d", slot))); err == nil {
			size, created = info.Size(), info.ModTime().Unix()
		}
	}
	if size > 0 && created > 0 {
		if ttl <= 0 || tags == "" {
			_, _, ettl, etags := serverLoad(prefix, slot)
			if ttl <= 0 {
				ttl = ettl
			}
			if tags == "" {
				tags = etags
			}
		}
		if content, err := json.Marshal(map[string]any{"size": size, "created": created, "ttl": ttl, "tags": tags}); err == nil {
			os.WriteFile(filepath.Join(prefix, fmt.Sprintf("%02d.meta", slot)), content, 0644)
		}
	}
}
func serverDelete(prefix string, slot int) {
	os.Remove(filepath.Join(prefix, fmt.Sprintf("%02d.meta", slot)))
	os.Remove(filepath.Join(prefix, fmt.Sprintf("%02d", slot)))
}

func serverHandle(response http.ResponseWriter, request *http.Request) {
	space, auth, _ := request.BasicAuth()
	if !rcache.Get(`^[a-z0-9_]{2,32}$`).MatchString(space) {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	if space == "" || !Config.GetBoolean(Config.Path(PROGNAME, "spaces", space, "enabled")) {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	match, aindex := acl.PasswordConfig(auth, Config, Config.Path(PROGNAME, "spaces", space, "auth"), false)
	if !match {
		response.WriteHeader(http.StatusUnauthorized)
		return
	}

	remote, _, _ := net.SplitHostPort(request.RemoteAddr)
	forward := Config.GetStrings(Config.Path(PROGNAME, "spaces", space, "forward"))
	if len(forward) == 0 {
		forward = []string{"127.0.0.0/8"}
	}
	if match, _ := acl.CIDR(remote, forward, false); match {
		if header := strings.TrimSpace(request.Header.Get("X-Forwarded-For")); header != "" {
			remote = header
		}
	}
	if match, _ := acl.CIDRConfig(remote, Config, Config.Path(PROGNAME, "spaces", space, "clients"), true); !match {
		response.WriteHeader(http.StatusForbidden)
		return
	}

	header := strings.TrimSpace(request.Header.Get("X-Slot"))
	slot, _ := strconv.Atoi(header)
	slots := int(Config.GetIntegerBounds(Config.Path(PROGNAME, "spaces", space, "slots"), 20, 1, 64))
	if header != "" && (slot < 1 || slot > slots) {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	ttl, _ := strconv.Atoi(strings.TrimSpace(request.Header.Get("X-TTL")))
	tags := strings.TrimSpace(request.Header.Get("X-Tags"))
	prefix := filepath.Join(Config.GetString(Config.Path(PROGNAME, "prefix"), "/tmp/"+PROGNAME), space)
	os.MkdirAll(prefix, 0755)

	response.Header().Set("Server", PROGNAME+"/"+PROGVER)
	switch request.Method {
	case http.MethodGet:
		if slot <= 0 {
			// list action
			list := [][]any{}
			for slot := 1; slot <= slots; slot++ {
				size, created, ttl, tags := serverLoad(prefix, slot)
				list = append(list, []any{size, created, ttl, tags})
			}
			if content, err := json.Marshal(list); err == nil {
				response.Header().Set("Content-Type", "application/json")
				response.Write(content)
				return
			}
		} else {
			// paste action
			http.ServeFile(response, request, fmt.Sprintf("%s/%02d", prefix, slot))
		}

	case http.MethodPost:
		// copy action
		if slot > 0 {
			if aindex != 0 {
				response.WriteHeader(http.StatusForbidden)
				return
			}
			if handle, err := os.CreateTemp(prefix, fmt.Sprintf("_%02d_", slot)); err != nil {
				response.WriteHeader(http.StatusForbidden)
				return
			} else {
				data, size, maxsize := make([]byte, 64<<10), 0, int(Config.GetSizeBounds(Config.Path(PROGNAME, "spaces", space, "size"), 4<<20, 1<<10, 4<<30))
				for {
					read, err := io.ReadAtLeast(request.Body, data, cap(data))
					if read > 0 {
						if size < maxsize {
							handle.Write(data[:read])
						}
						size += read
					}
					if err != nil {
						break
					}
				}
				handle.Close()
				if size < 32+24+1+16 { // salt + aead-nonce + data + aead-overhead
					response.WriteHeader(http.StatusBadRequest)
				} else if size < maxsize {
					os.Rename(handle.Name(), fmt.Sprintf("%s/%02d", prefix, slot))
					serverSave(prefix, slot, 0, 0, ttl, tags)
				} else {
					response.WriteHeader(http.StatusRequestEntityTooLarge)
				}
				os.Remove(handle.Name())
			}
			return
		}

	case http.MethodPatch:
		// update action
		if slot > 0 && (ttl != 0 || tags != "") {
			if aindex != 0 {
				response.WriteHeader(http.StatusForbidden)
				return
			}
			serverSave(prefix, slot, 0, 0, ttl, tags)
			return
		}

	case http.MethodDelete:
		// clean action
		if slot > 0 {
			if aindex != 0 {
				response.WriteHeader(http.StatusForbidden)
				return
			}
			serverDelete(prefix, slot)
			return
		}

	default:
		response.WriteHeader(http.StatusMethodNotAllowed)
	}
	response.WriteHeader(http.StatusBadRequest)
}

func Server() {
	go func() {
		for range time.Tick(5 * time.Second) {
			prefix := Config.GetString(Config.Path(PROGNAME, "prefix"), "/tmp/"+PROGNAME)
			filepath.Walk(prefix, func(path string, info fs.FileInfo, err error) error {
				if captures := rcache.Get(`/([^/]+)/(\d+)\.meta$`).FindStringSubmatch(path); captures != nil {
					slot, _ := strconv.Atoi(captures[2])
					if _, created, ttl, _ := serverLoad(filepath.Join(prefix, captures[1]), slot); created != 0 && ttl != 0 {
						if time.Since(time.Unix(created, 0).Add(time.Duration(ttl)*time.Second)) > 0 {
							serverDelete(filepath.Join(prefix, captures[1]), slot)
						}
					}
				}
				return nil
			})
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", serverHandle)
	if key := Config.GetStringMatch(Config.Path(PROGNAME, "listen"), "_", `^\s*(\S+)?:\S+\s*((,[^,]+){2})?$`); key != "_" {
		parts := []string{}
		for _, value := range strings.Split(key, ",") {
			if value = strings.TrimSpace(value); value != "" {
				parts = append(parts, value)
			}
		}
		parts[0] = strings.TrimLeft(parts[0], "*")
		server := &http.Server{
			Addr:              parts[0],
			Handler:           mux,
			ErrorLog:          log.New(io.Discard, "", 0),
			MaxHeaderBytes:    4 << 10,
			ReadHeaderTimeout: 15 * time.Second,
			ReadTimeout:       time.Hour,
			WriteTimeout:      time.Hour,
			IdleTimeout:       30 * time.Second,
		}
		if len(parts) == 3 {
			certificates := &dynacert.DYNACERT{}
			certificates.Add("*", parts[1], parts[2])
			server.TLSConfig, server.TLSNextProto = certificates.TLSConfig(), map[string]func(*http.Server, *tls.Conn, http.Handler){}
		}
		for {
			var err error

			if len(parts) == 3 {
				err = server.ListenAndServeTLS("", "")
			} else {
				err = server.ListenAndServe()
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			}
			time.Sleep(time.Second)
		}
	}
	fmt.Fprintf(os.Stderr, "missing or invalid \"listen\" parameter in configuration\n")
	os.Exit(1)
}
