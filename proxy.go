package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/elazarl/goproxy"
)

func handler(w http.ResponseWriter, r *http.Request) {
	method := r.Method
	url := r.URL
	headers := r.Header

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "OK")

	fmt.Printf("%s %s\n", method, url.Path)
	for header, value := range headers {
		fmt.Printf("> %s: %v\n", header, strings.Join(value, ","))
	}

	fmt.Print("\n")
}

func rewriteHeader(request *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	hello := request.Header.Get("X-Hello")
	request.Header.Set("X-Hello", fmt.Sprintf("Client said: %s", hello))

	return request, nil
}

func main() {
	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest().DoFunc(rewriteHeader)

	// start the proxy
	go func() {
		fmt.Print("proxy listening on 8128\n")
		log.Fatal(http.ListenAndServe(":8128", proxy))
	}()

	// act as a server backend too for testing.
	log.Fatal(http.ListenAndServe(":8080", http.HandlerFunc(handler)))
}
