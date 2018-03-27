
default: build run

build: ~/go/bin/rewrite-proxy

~/go/bin/rewrite-proxy: ./proxy.go
	go install github.com/charypar/rewrite-proxy

.PHONY: run
run: ~/go/bin/rewrite-proxy
	@~/go/bin/rewrite-proxy