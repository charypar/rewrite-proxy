package hsm

import (
	gocrypto "crypto"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/charypar/rewrite-proxy/crypto"
)

func TestEncryptDecrypt(t *testing.T) {
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

	session, err := New("/usr/local/lib/softhsm/libsofthsm2.so", "Test Token", "1234")
	if err != nil {
		t.Errorf("OpenSession() error = %v", err)
		return
	}

	key, err := session.FindKey("proxykey")
	if err != nil {
		t.Errorf("session.FindKey() error = %v", err)
		session.Close()
		return
	}

	want := []byte("Hello World!")

	t.Run("Encrypt with public key, decrypt with HSM", func(t *testing.T) {
		aesKey, err := key.DecryptOAEP(gocrypto.SHA1, encrypted.Key)
		if err != nil {
			t.Errorf("DecryptOAEP() error = %v", err)
			session.Close()
			return
		}

		decrypted, err := crypto.AESDecrypt(aesKey, encrypted.Data)
		if err != nil {
			t.Errorf("crypto.AESDecrypt() error = %v", err)
			session.Close()
			return
		}

		if !reflect.DeepEqual(decrypted, want) {
			t.Errorf("Decrypted text = %v, want %v", string(decrypted), string(want))
		}

		session.Close()
	})
}
