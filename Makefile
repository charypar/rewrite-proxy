GOPATH:=$(shell go env GOPATH)

default: build run

# Running and testing

.PHONY: run
run: $(GOPATH)/bin/rewrite-proxy
	@ LIB_HSM_PATH=/usr/local/lib/softhsm/libsofthsm2.so \
		SLOT_LABEL='Test Token' \
		SLOT_PIN=1234 \
		KEY_LABEL=proxykey \
		HEADER_NAME=X-Hello \
		PORT=3128 \
		TEST_PORT=8080 \
		$(GOPATH)/bin/rewrite-proxy

test: install
	@go test ./...

# Building

build: install $(GOPATH)/bin/rewrite-proxy

~/go/bin/rewrite-proxy: ./proxy.go
	@go install github.com/charypar/rewrite-proxy

# Dependencies

install: $(GOPATH)/src/github.com/elazarl/goproxy \
				 $(GOPATH)/src/github.com/miekg/pkcs11 \
				 $(GOPATH)/src/github.com/caarlos0/env

$(GOPATH)/src/github.com/elazarl/goproxy:
	go get github.com/elazarl/goproxy

$(GOPATH)/src/github.com/miekg/pkcs11:
	go get github.com/miekg/pkcs11

$(GOPATH)/src/github.com/caarlos0/env:
	go get github.com/caarlos0/env