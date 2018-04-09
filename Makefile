
default: build run

build: install ~/go/bin/rewrite-proxy

~/go/bin/rewrite-proxy: ./proxy.go
	go install github.com/charypar/rewrite-proxy

.PHONY: run
run: ~/go/bin/rewrite-proxy
	@~/go/bin/rewrite-proxy

install: ~/go/src/github.com/elazarl/goproxy ~/go/src/github.com/miekg/pkcs11

~/go/src/github.com/elazarl/goproxy:
	go get github.com/elazarl/goproxy

~/go/src/github.com/miekg/pkcs11:
	go get github.com/miekg/pkcs11