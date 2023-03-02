[![latest release](https://img.shields.io/github/release/pyke369/tarentula.svg)](https://github.com/pyke369/tarentula/releases/latest)
![tarentula](https://github.com/pyke369/tarentula/raw/master/support/logo.png)

Tarentula provides a way to easily and securely exchange content between multiple clients over a public network. It uses an intermediary HTTP(S) server (which knows absolutely nothing about the content being stored) and implements an end-to-end content encryption scheme between clients sharing the same encryption secret.

# Features
TODO

# Installation

### Use pre-compiled binaries
Thanks to Github actions and Go native cross-compilation support, pre-compiled binaries for a variety of operating systems and cpu architectures are available ![here](https://github.com/pyke369/tarentula/releases/latest). Pick the right one for you, uncompress after download and you should be good to go.

### Build from source code
Alternatively you may want to build the `tarentula` binary from source code, which can easily be done using the following command:

```
$ git clone https://github.com/pyke369/tarentula && cd tarentula && make
Cloning into 'tarentula'...
go: downloading github.com/pyke369/golang-support v0.0.0-20240310160822-0bf3991803a0
go: downloading golang.org/x/crypto v0.21.0
go: downloading golang.org/x/sys v0.18.0

$ ls -al tarentula
-rwxr-xr-x 1 pyke pyke 6325880 Mar 13 17:11 tarentula
```
or directly installing from the go toolchain:
```
$ go install github.com/pyke369/tarentula@latest
go: downloading github.com/pyke369/golang-support v0.0.0-20240310160822-0bf3991803a0
go: downloading golang.org/x/crypto v0.21.0
go: downloading golang.org/x/sys v0.18.0

$ ls -l $GOPATH/bin/tarentula
-rwxr-xr-x 1 pyke pyke 9338868 Mar 13 17:07 /tmp/go/bin/tarentula
```

In all cases you may want to move the resulting `tarentula` static binary somewhere within your execution path, and you should end up with a functionning `tarentula` for your platform:
```
$ tarentula
usage: tarentula <action> [<arguments>]

version
  display this program version and exit

server [<configuration>]
  run in server mode (default configuration file is /etc/taretula-server.conf)

list [json]
  list available slots

copy [<slot#|-> [<ttl|-> [<tag>...]]]
  store standard input content in specified slot# (default slot# is 1, default ttl is infinite, no tag by default)

update [<slot#|-> [<ttl|-> [<tag>...]]]
  update specified slot# ttl and/or tags (default slot# is 1, default ttl is infinite, no tag by default)

paste [<slot#>]
  restore content from specified slot# to standard output (default slot# is 1)

clean [<slot#>]
  cleanup specified slot (default slot# is 1)
```

# Configuration
TODO

# Usage
TODO

# License
MIT - Copyright (c) 2018-2023 Pierre-Yves Kerembellec
