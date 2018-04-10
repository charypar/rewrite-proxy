package main

import (
	gocrypto "crypto"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/caarlos0/env"
	"github.com/charypar/rewrite-proxy/crypto"
	"github.com/charypar/rewrite-proxy/hsm"
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
	encrypted, err := crypto.Encrypt(publicKey, gocrypto.SHA1, []byte(message))
	if err != nil {
		return "", fmt.Errorf("cannot encrypt message: %s", err)
	}

	marshalled, err := encrypted.Marshal()
	if err != nil {
		return "", fmt.Errorf("cannot marshal encrypted message: %s", err)
	}

	return string(marshalled), nil
}

func printTestMessage(headerName string) {
	publicKey, err := loadPublicKey("crypto/fixtures/rsa_pub.pem")
	if err != nil {
		log.Fatal(err)
	}

	message, err := encryptExample(publicKey, "Hello world!!!")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Try this in an %s header: \n%s\n\n", headerName, message)
}

// ---  ACTUAL PROXY IMPLEMENTATION ---

type proxyHandler struct {
	privateKey hsm.PKCS11PrivateKey
	headerName string
}

func (handler proxyHandler) Handle(request *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	ciphertext := request.Header.Get(handler.headerName)
	if len(ciphertext) < 1 {
		return request, nil
	}

	message, err := crypto.Unmarshal([]byte(ciphertext))
	if err != nil {
		log.Printf("could not parse %s header, ignoring", handler.headerName)
		request.Header.Del(handler.headerName)
		return request, nil
	}

	cleartext, err := message.DecryptHSM(handler.privateKey, gocrypto.SHA1)
	if err != nil {
		log.Printf("could not decrypt %s header, ignoring", handler.headerName)
		request.Header.Del(handler.headerName)
		return request, nil
	}

	request.Header.Set(handler.headerName, string(cleartext))

	return request, nil
}

// https://github.com/caarlos0/env
type proxyConfig struct {
	LibHSMPath string `env:"LIB_HSM_PATH,required"`
	SlotLabel  string `env:"SLOT_LABEL,required"`
	SlotPIN    string `env:"SLOT_PIN,required"`
	KeyLabel   string `env:"KEY_LABEL,required"`
	HeaderName string `env:"HEADER_NAME,required"`
	Port       string `env:"PORT,required"`
	TestPort   string `env:"TEST_PORT" envDefault:"8080"`
}

func main() {
	config := proxyConfig{}
	err := env.Parse(&config)
	if err != nil {
		log.Fatal(err)
	}

	session, err := hsm.New(config.LibHSMPath, config.SlotLabel, config.SlotPIN)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	privateKey, err := session.FindKey(config.KeyLabel)
	if err != nil {
		log.Fatal(err)
	}

	handler := proxyHandler{privateKey: privateKey, headerName: config.HeaderName}

	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest().Do(handler)

	printTestMessage(config.HeaderName)

	// start the proxy
	go func() {
		log.Printf("proxy listening on %s\n", config.Port)
		log.Fatal(http.ListenAndServe(":"+config.Port, proxy))
	}()

	// act as a server backend too for testing.
	log.Fatal(http.ListenAndServe(":"+config.TestPort, http.HandlerFunc(debugHandler)))
}
