package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	j "github.com/pyke369/golang-support/jsonrpc"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

func clientSize(size int64) string {
	if size == 0 {
		return "-"
	} else if size < 1<<10 {
		return fmt.Sprintf("%d", size)
	} else if size < 1<<20 {
		return fmt.Sprintf("%.1f kB", float64(size)/float64(1<<10))
	} else if size < 1<<30 {
		return fmt.Sprintf("%.2f MB", float64(size)/float64(1<<20))
	}
	return fmt.Sprintf("%.3f GB", float64(size)/float64(1<<30))
}
func clientCreated(stamp int64) string {
	if stamp == 0 {
		return "-"
	}
	return time.Unix(stamp, 0).Format("2006-01-02 15:04:05")
}
func clientTTL(stamp, ttl int64) string {
	if stamp == 0 {
		return "-"
	}
	if ttl == 0 {
		return "infinite"
	}
	left := -int(time.Since(time.Unix(stamp, 0).Add(time.Duration(ttl)*time.Second)) / time.Second)
	if left <= 0 {
		return "-"
	}
	if left < 60 {
		return fmt.Sprintf("%ds", left)
	}
	days, hours, minutes, value := 0, 0, 0, ""
	days = left / 86400
	left -= days * 86400
	hours = left / 3600
	left -= hours * 3600
	minutes = left / 60
	if days != 0 {
		value += fmt.Sprintf("%dd", days)
	}
	if hours != 0 {
		value += fmt.Sprintf("%dh", hours)
	}
	if minutes != 0 {
		value += fmt.Sprintf("%dmn", minutes)
	}
	return value
}
func clientTags(input, secret string, alt bool) (output string) {
	if data, err := base64.StdEncoding.DecodeString(input); err == nil && len(data) >= 32+24+2+16 && len(data) < 3<<10 { // salt + aead-nonce + data + aead-overhead
		if aead, err := chacha20poly1305.NewX(argon2.IDKey([]byte(secret), data[:32], 1, 64<<10, 1, 32)); err == nil {
			nonce, overhead := aead.NonceSize(), aead.Overhead()
			if _, err = aead.Open(data[32+nonce:32+nonce], data[32:32+nonce], data[32+nonce:], nil); err == nil {
				tags := map[string]string{}
				if json.Unmarshal(data[32+nonce:len(data)-overhead], &tags) == nil {
					names := []string{}
					for name := range tags {
						names = append(names, name)
					}
					sort.Strings(names)
					if alt {
						output = "{ "
					}
					for _, name := range names {
						if alt {
							output += fmt.Sprintf("\"%s\":\"%s\", ", name, tags[name])
						} else {
							output += fmt.Sprintf("%s:%s ", name, tags[name])
						}
					}
					if alt {
						output = strings.TrimRight(output, ", ")
						output += " }"
					}
					return strings.TrimSpace(output)
				}
			}
		}
	}
	if alt {
		return "{}"
	} else {
		return "-"
	}
}
func clientCypher(tags []byte, secret string) string {
	data := make([]byte, 3<<10)
	rand.Read(data[:32])
	if aead, err := chacha20poly1305.NewX(argon2.IDKey([]byte(secret), data[:32], 1, 64<<10, 1, 32)); err == nil {
		nonce, overhead := aead.NonceSize(), aead.Overhead()
		if len(tags) > cap(data)-32-nonce-overhead {
			return ""
		}
		rand.Read(data[32 : 32+nonce])
		copy(data[32+nonce:], tags)
		aead.Seal(data[32+nonce:32+nonce], data[32:32+nonce], data[32+nonce:32+nonce+len(tags)], nil)
		return base64.StdEncoding.EncodeToString(data[:32+nonce+len(tags)+overhead])
	}
	return ""
}

func clientList(remote, space, auth, secret string, alt bool) int {
	request, _ := http.NewRequest(http.MethodGet, remote, nil)
	request.Header.Set("User-Agent", PROGNAME+"/"+PROGVER)
	request.SetBasicAuth(space, auth)
	client := &http.Client{Timeout: 15 * time.Second}
	if response, err := client.Do(request); err == nil {
		if response.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "%d %s\n", response.StatusCode, strings.ToLower(http.StatusText(response.StatusCode)))
			return 1
		}
		body, _ := io.ReadAll(response.Body)
		list := [][]any{}
		if err := json.Unmarshal(body, &list); err == nil {
			if alt {
				fmt.Printf("[\n")
			} else {
				fmt.Printf("%-4.4s  %-10.10s  %-19.19s  %-13.13s  %s\n"+
					"----  ----        -------              ---            ----\n",
					"slot", "size", "created", "ttl", "tags")
			}
			for index, slot := range list {
				if len(slot) >= 4 {
					size := int64(j.Number(slot[0]))
					if size != 0 {
						size -= 32
						chunks := size / (64 << 10)
						if size%(64<<10) != 0 {
							size -= (chunks + 1) * 40
						} else {
							size -= chunks * 40
						}
					}
					if alt {
						fmt.Printf("  { \"slot\":%d, \"size\":%d, \"created\":%d, \"ttl\":%d, \"tags\":%s }",
							index+1, size,
							int64(j.Number(slot[1])),
							int64(j.Number(slot[2])),
							clientTags(j.String(slot[3]), secret, true),
						)
						if index < len(list)-1 {
							fmt.Printf(",")
						}
						fmt.Printf("\n")
					} else {
						fmt.Printf("%-4d  %-10.10s  %-19.19s  %-13.13s  %s\n",
							index+1,
							clientSize(size),
							clientCreated(int64(j.Number(slot[1]))),
							clientTTL(int64(j.Number(slot[1])), int64(j.Number(slot[2]))),
							clientTags(j.String(slot[3]), secret, false),
						)
					}
				}
			}
			if alt {
				fmt.Printf("]\n")
			}
		} else {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			return 1
		}
	} else {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		return 1
	}
	return 0
}

func clientCopy(remote, space, auth, secret string, slot, ttl int, tags map[string]string) int {
	if slot <= 0 {
		fmt.Fprintf(os.Stderr, "invalid slot\n")
		return 1
	}
	reader, writer := io.Pipe()
	size := 0
	go func() {
		data := make([]byte, 64<<10)
		rand.Read(data[:32])
		writer.Write(data[:32])
		if aead, err := chacha20poly1305.NewX(argon2.IDKey([]byte(secret), data[:32], 1, 64<<10, 1, 32)); err == nil {
			nonce, overhead := aead.NonceSize(), aead.Overhead()
			for {
				read, err := io.ReadAtLeast(os.Stdin, data[nonce:cap(data)-overhead], cap(data)-nonce-overhead)
				if read > 0 {
					rand.Read(data[:nonce])
					aead.Seal(data[nonce:nonce], data[:nonce], data[nonce:nonce+read], nil)
					writer.Write(data[:nonce+read+overhead])
					size += read
				}
				if err != nil {
					break
				}
			}
		}
		writer.Close()
	}()
	request, _ := http.NewRequest(http.MethodPost, remote, reader)
	request.SetBasicAuth(space, auth)
	request.Header.Set("User-Agent", PROGNAME+"/"+PROGVER)
	request.Header.Set("X-Slot", strconv.Itoa(slot))
	if ttl != 0 {
		request.Header.Set("X-TTL", strconv.Itoa(ttl))
	}
	if len(tags) != 0 {
		if payload, err := json.Marshal(tags); err == nil {
			if cyphered := clientCypher(payload, secret); cyphered != "" {
				request.Header.Set("X-Tags", cyphered)
			}
		}
	}
	client := &http.Client{Timeout: time.Hour}
	if response, err := client.Do(request); err == nil {
		if response.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "%d %s\n", response.StatusCode, strings.ToLower(http.StatusText(response.StatusCode)))
			return 1
		}
		if j.Bool(os.Getenv(strings.ToUpper(PROGNAME) + "_VERBOSE")) {
			fmt.Fprintf(os.Stderr, "copied %d byte(s) to slot %d\n", size, slot)
		}
	} else {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		return 1
	}
	return 0
}

func clientUpdate(remote, space, auth, secret string, slot, ttl int, tags map[string]string) int {
	if slot <= 0 {
		fmt.Fprintf(os.Stderr, "invalid slot\n")
		return 1
	}
	if ttl == 0 && len(tags) == 0 {
		fmt.Fprintf(os.Stderr, "either ttl or tags must be provided\n")
		return 1
	}
	request, _ := http.NewRequest(http.MethodPatch, remote, nil)
	request.SetBasicAuth(space, auth)
	request.Header.Set("User-Agent", PROGNAME+"/"+PROGVER)
	request.Header.Set("X-Slot", strconv.Itoa(slot))
	if ttl != 0 {
		request.Header.Set("X-TTL", strconv.Itoa(ttl))
	}
	if len(tags) != 0 {
		if payload, err := json.Marshal(tags); err == nil {
			if cyphered := clientCypher(payload, secret); cyphered != "" {
				request.Header.Set("X-Tags", cyphered)
			}
		}
	}
	client := &http.Client{Timeout: 15 * time.Second}
	if response, err := client.Do(request); err == nil {
		if response.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "%d %s\n", response.StatusCode, strings.ToLower(http.StatusText(response.StatusCode)))
			return 1
		}
		if j.Bool(os.Getenv(strings.ToUpper(PROGNAME) + "_VERBOSE")) {
			fmt.Fprintf(os.Stderr, "updated slot %d\n", slot)
		}
	} else {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		return 1
	}
	return 0
}

func clientPaste(remote, space, auth, secret string, slot int) int {
	if slot <= 0 {
		fmt.Fprintf(os.Stderr, "invalid slot\n")
		return 1
	}
	request, _ := http.NewRequest(http.MethodGet, remote, nil)
	request.Header.Set("User-Agent", PROGNAME+"/"+PROGVER)
	request.SetBasicAuth(space, auth)
	request.Header.Set("X-Slot", strconv.Itoa(slot))
	client := &http.Client{Timeout: time.Hour}
	if response, err := client.Do(request); err == nil {
		if response.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "%d %s\n", response.StatusCode, strings.ToLower(http.StatusText(response.StatusCode)))
			return 1
		}
		data := make([]byte, 64<<10)
		if _, err := io.ReadAtLeast(response.Body, data[:32], 32); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			return 1
		}
		if aead, err := chacha20poly1305.NewX(argon2.IDKey([]byte(secret), data[:32], 1, 64<<10, 1, 32)); err == nil {
			size, nonce, overhead := 0, aead.NonceSize(), aead.Overhead()
			for {
				read, err := io.ReadAtLeast(response.Body, data, cap(data))
				if read > nonce+overhead {
					if _, err = aead.Open(data[nonce:nonce], data[:nonce], data[nonce:read], nil); err == nil {
						os.Stdout.Write(data[nonce : read-overhead])
						size += read - nonce - overhead
					} else {
						fmt.Fprintf(os.Stderr, "%s\n", err.Error())
						return 1
					}
				}
				if err != nil || read <= nonce+overhead {
					break
				}
			}
			if j.Bool(os.Getenv(strings.ToUpper(PROGNAME) + "_VERBOSE")) {
				fmt.Fprintf(os.Stderr, "pasted %d byte(s) from slot %d\n", size, slot)
			}
		}
	}
	return 0
}

func clientClean(remote, space, auth string, slot int) int {
	if slot <= 0 {
		fmt.Fprintf(os.Stderr, "invalid slot\n")
		return 1
	}
	request, _ := http.NewRequest(http.MethodDelete, remote, nil)
	request.SetBasicAuth(space, auth)
	request.Header.Set("User-Agent", PROGNAME+"/"+PROGVER)
	request.Header.Set("X-Slot", strconv.Itoa(slot))
	client := &http.Client{Timeout: 15 * time.Second}
	if response, err := client.Do(request); err == nil {
		if response.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "%d %s\n", response.StatusCode, strings.ToLower(http.StatusText(response.StatusCode)))
			return 1
		}
		if j.Bool(os.Getenv(strings.ToUpper(PROGNAME) + "_VERBOSE")) {
			fmt.Fprintf(os.Stderr, "cleaned slot %d\n", slot)
		}
	} else {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		return 1
	}
	return 0
}

func Client(action string, slot, ttl int, tags map[string]string) {
	remote, space := strings.TrimSpace(Config.GetString(Config.Path(PROGNAME, "remote"))), strings.TrimSpace(Config.GetString(Config.Path(PROGNAME, "space")))
	auth, secret := strings.TrimSpace(Config.GetString(Config.Path(PROGNAME, "auth"))), strings.TrimSpace(Config.GetString(Config.Path(PROGNAME, "secret")))
	if remote == "" || space == "" || auth == "" {
		fmt.Fprintf(os.Stderr, "missing or invalid \"remote\", \"space\" or \"auth\" parameter in configuration\n")
		os.Exit(1)
	}
	if (action == "copy" || action == "paste") && len(secret) < 32 {
		fmt.Fprintf(os.Stderr, "missing or invalid \"secret\" parameter in configuration (must be at least 32 characters long)\n")
		os.Exit(1)
	}
	if !strings.HasPrefix(remote, "http") {
		remote = "https://" + remote
	}
	switch action {
	case "list":
		os.Exit(clientList(remote, space, auth, secret, len(os.Args) > 2 && os.Args[2] == "json"))
	case "copy":
		os.Exit(clientCopy(remote, space, auth, secret, slot, ttl, tags))
	case "update":
		os.Exit(clientUpdate(remote, space, auth, secret, slot, ttl, tags))
	case "paste":
		os.Exit(clientPaste(remote, space, auth, secret, slot))
	case "clean":
		os.Exit(clientClean(remote, space, auth, slot))
	}
}
