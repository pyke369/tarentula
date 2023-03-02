package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/uconfig"
)

const (
	PROGNAME = "tarentula"
	PROGVER  = "1.0.7"
)

var Config *uconfig.UConfig

func exists(path string) (output string) {
	if handle, err := os.Open(path); err == nil && path != "" {
		output = path
		handle.Close()
	}
	return
}

func main() {
	var err error

	config := exists(os.Getenv(strings.ToUpper(PROGNAME) + "_CONFIG"))
	if len(os.Args) > 1 {
		action := strings.ToLower(os.Args[1])
		switch action {
		case "version":
			fmt.Printf("%s %s\n", PROGNAME, PROGVER)
			os.Exit(0)

		case "server":
			if len(os.Args) > 2 {
				config = exists(os.Args[2])
			}
			if config == "" {
				config = exists("/etc/" + PROGNAME + "-server.conf")
			}
			if config != "" {
				if Config, err = uconfig.New(config); err != nil {
					fmt.Fprintf(os.Stderr, "configuration syntax error: %s\n", err.Error())
					os.Exit(1)
				}
				go func() {
					signals := make(chan os.Signal, 1)
					signal.Notify(signals, syscall.SIGHUP)
					for {
						<-signals
						if _, err = uconfig.New(config); err == nil {
							Config.Load(config)
						} else {
							fmt.Fprintf(os.Stderr, "configuration syntax error: %s\n", err.Error())
						}
					}
				}()
				Server()
			}
			fmt.Fprintf(os.Stderr, "no configuration found\n")
			os.Exit(1)

		case "list", "copy", "update", "paste", "clean":
			if home := os.Getenv("HOME"); config == "" && home != "" {
				for _, path := range []string{home + "/." + PROGNAME + "-client.conf", home + "/.config/" + PROGNAME + "-client.conf", "/etc/" + PROGNAME + "-client.conf"} {
					if config = exists(path); config != "" {
						break
					}
				}
			}
			if config != "" {
				if Config, err = uconfig.New(config); err != nil {
					fmt.Fprintf(os.Stderr, "configuration syntax error: %s\n", err.Error())
					os.Exit(1)
				}
				slot, ttl, tags := 1, 0, map[string]string{}
				if len(os.Args) > 2 {
					if value, _ := strconv.Atoi(strings.TrimSpace(os.Args[2])); value > 0 {
						slot = value
					}
				}
				if len(os.Args) > 3 {
					if value, _ := strconv.Atoi(strings.TrimSpace(os.Args[3])); value >= 60 {
						ttl = value
					}
				}
				if len(os.Args) > 4 {
					for _, tag := range os.Args[4:] {
						if captures := rcache.Get(`^([^=:]+)[=:](.+)$`).FindStringSubmatch(strings.TrimSpace(tag)); captures != nil {
							tags[strings.ToLower(strings.TrimSpace(captures[1]))] = strings.TrimSpace(captures[2])
						}
					}
				}
				Client(action, slot, ttl, tags)
			}
			fmt.Fprintf(os.Stderr, "no configuration found\n")
			os.Exit(1)
		}
	}

	fmt.Fprintf(os.Stderr, "usage: "+
		"%s <action> [<arguments>]\n\n"+
		"version\n"+
		"  display this program version and exit\n\n"+
		"server [<configuration>]\n"+
		"  run in server mode (default configuration file is /etc/taretula-server.conf)\n\n"+
		"list [json]\n"+
		"  list available slots\n\n"+
		"copy [<slot#|-> [<ttl|-> [<tag>...]]]\n"+
		"  store standard input content in specified slot# (default slot# is 1, default ttl is infinite, no tag by default)\n\n"+
		"update [<slot#|-> [<ttl|-> [<tag>...]]]\n"+
		"  update specified slot# ttl and/or tags (default slot# is 1, default ttl is infinite, no tag by default)\n\n"+
		"paste [<slot#>]\n"+
		"  restore content from specified slot# to standard output (default slot# is 1)\n\n"+
		"clean [<slot#>]\n"+
		"  cleanup specified slot (default slot# is 1)\n",
		PROGNAME)
	os.Exit(1)
}
