package hsm

import (
	"C"
	"fmt"

	"github.com/miekg/pkcs11"
)
import (
	"crypto"
	"errors"
	"unsafe"
)

func ulongToBytes(n uint) []byte {
	return C.GoBytes(unsafe.Pointer(&n), C.sizeof_ulong) // ugh!
}

func concat(slices ...[]byte) []byte {
	n := 0
	for _, slice := range slices {
		n += len(slice)
	}
	r := make([]byte, n)
	n = 0
	for _, slice := range slices {
		n += copy(r[n:], slice)
	}
	return r
}

func pkcs11hash(hashFunction crypto.Hash) (hashAlg uint, mfg uint, err error) {
	switch hashFunction {
	case crypto.SHA1:
		return pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, nil
	case crypto.SHA224:
		return pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224, nil
	case crypto.SHA256:
		return pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, nil
	case crypto.SHA384:
		return pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, nil
	case crypto.SHA512:
		return pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, nil
	default:
		return 0, 0, errors.New("unsuported hash algorithm")
	}
}

func DecryptRSAOEAPsha256(ciphertext []byte, hash crypto.Hash) ([]byte, error) {
	nothing := make([]byte, 0)
	p := pkcs11.New("/usr/local/lib/softhsm/libsofthsm2.so")

	err := p.Initialize()
	if err != nil {
		return nothing, err
	}
	defer p.Destroy()
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		return nothing, err
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nothing, err
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, "1234")
	if err != nil {
		return nothing, err
	}
	defer p.Logout(session)

	err = p.FindObjectsInit(session, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, "proxykey")})
	if err != nil {
		return nothing, err
	}

	handles, _, err := p.FindObjects(session, 1)
	if err != nil {
		return nothing, err
	}
	p.FindObjectsFinal(session)

	privateKey := handles[0]

	hashAlg, mgf, err := pkcs11hash(hash)
	if err != nil {
		return nothing, fmt.Errorf("cannot select a hash function: %s", err)
	}

	OEAPParams := concat(
		ulongToBytes(hashAlg),
		ulongToBytes(mgf),
		ulongToBytes(pkcs11.CKZ_DATA_SPECIFIED),
		ulongToBytes(0),
		ulongToBytes(0),
	)

	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, OEAPParams)}
	err = p.DecryptInit(session, mechanism, privateKey)
	if err != nil {
		return nothing, fmt.Errorf("could not initialse decryption: %s", err)
	}

	plaintext, err := p.Decrypt(session, ciphertext)
	if err != nil {
		return nothing, fmt.Errorf("could not decrypt: %s", err)
	}

	p.DecryptFinal(session)

	return plaintext, nil
}
