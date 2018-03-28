package main

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/charypar/rewrite-proxy/crypto"
	"github.com/elazarl/goproxy"
)

// --- FUNCTIONS FOR TESTING PURPOSES ONLY ---

// For testing purposes only, logs all requests and
// their details
func debugHandler(w http.ResponseWriter, r *http.Request) {
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

func loadPrivateKey(file string) (*rsa.PrivateKey, error) {
	priKey, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("cannot read private key file: %s", err)
	}

	privateKey, err := crypto.ReadRSAPrivateKey(priKey)
	if err != nil {
		return nil, fmt.Errorf("cannot parse private key file: %s", err)
	}

	return privateKey, nil
}

func loadPublicKey(file string) (*rsa.PublicKey, error) {
	priKey, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("cannot read public key file: %s", err)
	}

	privateKey, err := crypto.ReadRSAPublicKey(priKey)
	if err != nil {
		return nil, fmt.Errorf("cannot parse public key file: %s", err)
	}

	return privateKey, nil
}

func encryptExample(publicKey *rsa.PublicKey, message string) (string, error) {
	encrypted, err := crypto.Encrypt(publicKey, []byte(message))
	if err != nil {
		return "", fmt.Errorf("cannot encrypt message: %s", err)
	}

	marshalled, err := encrypted.Marshal()
	if err != nil {
		return "", fmt.Errorf("cannot marshal encrypted message: %s", err)
	}

	return string(marshalled), nil
}

// ---  ACTUAL PROXY IMPLEMENTATION ---

type proxyHandler struct {
	PrivateKey *rsa.PrivateKey
}

func (handler proxyHandler) Handle(request *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	ciphertext := request.Header.Get("X-Hello")
	if len(ciphertext) < 1 {
		return request, nil
	}

	message, err := crypto.Unmarshal([]byte(ciphertext))
	if err != nil {
		log.Printf("could not parse X-Hello header, ignoring")
		request.Header.Del("X-Hello")
		return request, nil
	}

	cleartext, err := message.Decrypt(handler.PrivateKey)
	if err != nil {
		log.Printf("could not decrypt X-Hello header, ignoring")
		request.Header.Del("X-Hello")
		return request, nil
	}

	request.Header.Set("X-Hello", fmt.Sprintf("Client said: %s", string(cleartext)))

	return request, nil
}

func main() {
	privateKey, err := loadPrivateKey("crypto/fixtures/rsa.pem")
	if err != nil {
		log.Fatal(err)
	}

	publicKey, err := loadPublicKey("crypto/fixtures/rsa_pub.pem")
	if err != nil {
		log.Fatal(err)
	}

	message, err := encryptExample(publicKey, "Hello world!!!")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Try this in an X-Hello header: \n%s\n\n", message)

	handler := proxyHandler{PrivateKey: privateKey}
	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest().Do(handler)

	// start the proxy
	go func() {
		log.Print("proxy listening on 3128\n")
		log.Fatal(http.ListenAndServe(":3128", proxy))
	}()

	// act as a server backend too for testing.
	log.Fatal(http.ListenAndServe(":8080", http.HandlerFunc(debugHandler)))
}
