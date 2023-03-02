#!/bin/sh

PROGNAME=tarentula
CONFIG=TARENTULA_CONFIG
VERBOSE=TARENTULA_VERBOSE

# build targets
$(PROGNAME): *.go
	@env GOPATH=/tmp/go go get -d && env GOPATH=/tmp/go CGO_ENABLED=0 GOARCH=${_GOARCH} GOOS=${_GOOS} go build -trimpath -o $(PROGNAME)
	@-strip $(PROGNAME) 2>/dev/null || true
distclean:
	@rm -f $(PROGNAME) *.upx

# run targets
server: $(PROGNAME)
	@./$(PROGNAME) server support/_server.conf
list: $(PROGNAME)
	@env $(CONFIG)=support/_client.conf ./$(PROGNAME) list
jlist: $(PROGNAME)
	@env $(CONFIG)=support/_client.conf ./$(PROGNAME) list json
copy: $(PROGNAME)
	@echo $(PROGNAME) |env $(CONFIG)=support/_client.conf $(VERBOSE)=1 ./$(PROGNAME) copy 4 - tag1:value1 tag2:value2
update: $(PROGNAME)
	@env $(CONFIG)=support/_client.conf $(VERBOSE)=1 ./$(PROGNAME) update 4 7200 tag3:value3
paste: $(PROGNAME)
	@env $(CONFIG)=support/_client.conf $(VERBOSE)=1 ./$(PROGNAME) paste 4
clean: $(PROGNAME)
	@env $(CONFIG)=support/_client.conf $(VERBOSE)=1 ./$(PROGNAME) clean 4
