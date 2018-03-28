package crypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

// ReadRSAPublicKey reads a PEM encoded public key
func ReadRSAPublicKey(pemBlock []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBlock)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("could not decode public key, does not seem to be a valid PEM block")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse public key: %s", err)
	}

	switch key := key.(type) {
	case *rsa.PublicKey:
		return key, nil
	case *dsa.PublicKey:
		return nil, fmt.Errorf("expected an RSA public key, got DSA")
	case *ecdsa.PublicKey:
		return nil, fmt.Errorf("expected an RSA public key, got ECDSA")
	default:
		return nil, fmt.Errorf("expected an RSA public key, got an unknown key type")
	}
}

// ReadRSAPrivateKey reads a PEM encoded RSA public key
func ReadRSAPrivateKey(pemBlock []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBlock)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("could not decode private key, does not seem to be a valid PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse private key: %s", err)
	}

	return key, nil
}

// Unmarshal creates an EncryptedMessage by umarshalling JSON
func Unmarshal(jsonString []byte) (EncryptedMessage, error) {
	token := EncryptedMessage{}

	err := json.Unmarshal(jsonString, &token)
	if err != nil {
		return EncryptedMessage{}, err
	}

	return token, nil
}

// Encrypt a message using an RSA public key. The message is encrypted
// with an AES stream ocopher with a randomly generated single-use key
// The key itself is then encrypted with RSA.
func Encrypt(publicKey *rsa.PublicKey, message []byte) (EncryptedMessage, error) {
	aesKey := make([]byte, 32)
	_, err := rand.Read(aesKey)
	if err != nil {
		return EncryptedMessage{}, fmt.Errorf("error generating key: %s", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return EncryptedMessage{}, fmt.Errorf("error initializing AES cipher: %s", err)
	}

	ciphertext := make([]byte, block.BlockSize()+len(message))
	iv := ciphertext[:block.BlockSize()]

	if _, err := rand.Read(iv); err != nil {
		return EncryptedMessage{}, fmt.Errorf("error generating random IV: %s", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], message)

	encKey, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, publicKey, aesKey, make([]byte, 0))
	if err != nil {
		return EncryptedMessage{}, fmt.Errorf("error encrypting the AES key: %s", err)
	}

	return EncryptedMessage{encKey, ciphertext}, nil
}

// EncryptedMessage holds an AES encrypted `Data` and an
// RSA public-key encrypted `Key`
type EncryptedMessage struct {
	Key  []byte `json:"encryptedKey"`
	Data []byte `json:"data"`
}

// Marshal serializes an encrypted token as JSON
func (message EncryptedMessage) Marshal() ([]byte, error) {
	return json.Marshal(message)
}

// Decrypt the EncryptedMessage with a given RSA private key
func (message EncryptedMessage) Decrypt(privateKey *rsa.PrivateKey) ([]byte, error) {
	nothing := make([]byte, 0)

	sha := crypto.SHA256.New()
	rng := rand.Reader
	aesKey, err := rsa.DecryptOAEP(sha, rng, privateKey, message.Key, nothing)
	if err != nil {
		return nothing, fmt.Errorf("error decrypting the AES key: %s", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nothing, fmt.Errorf("error initializinng AES with the message key: %s", err)
	}

	plaintext := make([]byte, len(message.Data)-aes.BlockSize)
	iv := message.Data[:block.BlockSize()]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plaintext, message.Data[block.BlockSize():])

	return plaintext, nil
}
