package hsm

import (
	gocrypto "crypto"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/charypar/rewrite-proxy/crypto"
)

func TestDecryptRSAOEAPsha256(t *testing.T) {
	pubKey, err := ioutil.ReadFile("../crypto/fixtures/rsa_pub.pem")
	if err != nil {
		t.Errorf("Cannot read public key: %s", err)
		return
	}

	publicKey, err := crypto.ReadRSAPublicKey(pubKey)
	if err != nil {
		t.Errorf("Cannot parse public key: %s", err)
	}

	message := []byte("Hello World!")
	encrypted, err := crypto.Encrypt(publicKey, gocrypto.SHA1, message)
	if err != nil {
		t.Errorf("Encrypt() error = %s", err)
		return
	}

	tests := []struct {
		name       string
		ciphertext []byte
		want       []byte
		wantErr    bool
	}{
		{
			"Decrypt AES key with HSM",
			encrypted.Key,
			[]byte("Hello World!"),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aesKey, err := DecryptRSAOEAPsha256(tt.ciphertext, gocrypto.SHA1)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptRSAOEAPsha256() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			decrypted, err := crypto.AESDecrypt(aesKey, encrypted.Data)
			if (err != nil) != tt.wantErr {
				t.Errorf("crypto.AESDecrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(decrypted, tt.want) {
				t.Errorf("DecryptRSAOEAPsha256() = %v, want %v", string(decrypted), string(tt.want))
			}
		})
	}
}
