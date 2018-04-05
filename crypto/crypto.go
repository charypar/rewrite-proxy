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

var noBytes []byte

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

// RSAEncrypt encrypts a message with an RSA public key using the hashFunction
// for padding the message
func RSAEncrypt(key *rsa.PublicKey, hashFunction crypto.Hash, message []byte) ([]byte, error) {
	return rsa.EncryptOAEP(hashFunction.New(), rand.Reader, key, message, make([]byte, 0))
}

// AESEncrypt encrtpys a message with a randomly generated key using the AES
// stream cipher and returns the ciphertext and the key
func AESEncrypt(message []byte) (ciphertext []byte, key []byte, err error) {
	key = make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		return noBytes, noBytes, fmt.Errorf("error generating key: %s", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return noBytes, noBytes, fmt.Errorf("error initializing AES cipher: %s", err)
	}

	ciphertext = make([]byte, block.BlockSize()+len(message))
	iv := ciphertext[:block.BlockSize()]

	if _, err := rand.Read(iv); err != nil {
		return noBytes, noBytes, fmt.Errorf("error generating random IV: %s", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], message)

	return ciphertext, key, nil
}

// Encrypt a message using an RSA public key. The message is encrypted
// with an AES stream ocopher with a randomly generated single-use key
// The key itself is then encrypted with RSA.
func Encrypt(publicKey *rsa.PublicKey, hashFunction crypto.Hash, message []byte) (EncryptedMessage, error) {
	ciphertext, aesKey, err := AESEncrypt(message)
	if err != nil {
		return EncryptedMessage{}, fmt.Errorf("AES encryption failed: %s", err)
	}

	encKey, err := RSAEncrypt(publicKey, hashFunction, aesKey)
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

// RSADecrypt decrypts a ciphertext with a given RSA private key, using the hashFunction
// as random oracle for padding (see crypto/rsa.DrcryptOAEP)
func RSADecrypt(privateKey *rsa.PrivateKey, hashFunction crypto.Hash, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(hashFunction.New(), rand.Reader, privateKey, ciphertext, noBytes)
}

// AESDecrypt decrypts a ciphertext with a given AES key
func AESDecrypt(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return noBytes, fmt.Errorf("error initializinng AES with the message key: %s", err)
	}

	plaintext := make([]byte, len(ciphertext)-aes.BlockSize)
	iv := ciphertext[:block.BlockSize()]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plaintext, ciphertext[block.BlockSize():])

	return plaintext, nil
}

// Decrypt the EncryptedMessage with a given RSA private key
func (message EncryptedMessage) Decrypt(privateKey *rsa.PrivateKey, hashFunction crypto.Hash) ([]byte, error) {
	aesKey, err := RSADecrypt(privateKey, hashFunction, message.Key)
	if err != nil {
		return noBytes, fmt.Errorf("error decrypting the AES key: %s", err)
	}

	return AESDecrypt(aesKey, message.Data)
}
