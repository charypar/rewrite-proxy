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

// Session is an open session with a Hardware Security Module
type Session struct {
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
}

func findSlot(tokenLabel string, p *pkcs11.Ctx) (uint, error) {
	slots, err := p.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("unable to get HSM slot list %s", err)
	}

	for i := range slots {
		token, err := p.GetTokenInfo(slots[i])
		if err != nil {
			continue
		}

		if token.Label == tokenLabel {
			return slots[i], nil
		}
	}

	return 0, fmt.Errorf("slot with token labeled '%s' not found", tokenLabel)
}

// New starts a HSM session using a given library (the .so binary),
// opens the selected slot and logs in with a pin
func New(libPath string, slotLabel string, pin string) (Session, error) {
	nothing := Session{}
	p := pkcs11.New(libPath)

	err := p.Initialize()
	if err != nil {
		return nothing, fmt.Errorf("cannot initialise a HSM connection: %s", err)
	}

	slotID, err := findSlot(slotLabel, p)
	if err != nil {
		return nothing, err
	}

	session, err := p.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nothing, fmt.Errorf("cannot start a HSM session: %s", err)
	}

	err = p.Login(session, pkcs11.CKU_USER, "1234")
	if err != nil {
		return nothing, fmt.Errorf("cannot log in with a HSM: %s", err)
	}

	return Session{ctx: p, session: session}, nil
}

// Close terminates the given session
func (session Session) Close() {
	session.ctx.Logout(session.session)
	session.ctx.CloseSession(session.session)
	session.ctx.Destroy()
	session.ctx.Finalize()
}

// FindKey finda a key with a given label and returns it
func (session Session) FindKey(label string) (PKCS11PrivateKey, error) {
	nothing := PKCS11PrivateKey{}
	p := session.ctx
	s := session.session

	err := p.FindObjectsInit(s, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, label)})
	if err != nil {
		return nothing, fmt.Errorf("Cannot find private key with label %s: %s", label, err)
	}

	handles, _, err := p.FindObjects(s, 1)
	if err != nil {
		return nothing, fmt.Errorf("Cannot find private key with label %s: %s", label, err)
	}
	p.FindObjectsFinal(s)

	return PKCS11PrivateKey{session, handles[0]}, nil
}

// PKCS11PrivateKey represents a Private Key in the HSM
type PKCS11PrivateKey struct {
	session Session
	handle  pkcs11.ObjectHandle
}

// DecryptOAEP uses the private key to decrypt a message using a given hash
// for message padding
func (key PKCS11PrivateKey) DecryptOAEP(hash crypto.Hash, ciphertext []byte) ([]byte, error) {
	var noBytes []byte
	p := key.session.ctx
	s := key.session.session

	hashAlg, mgf, err := pkcs11hash(hash)
	if err != nil {
		return noBytes, fmt.Errorf("cannot select a hash function: %s", err)
	}

	OEAPParams := concat(
		ulongToBytes(hashAlg),
		ulongToBytes(mgf),
		ulongToBytes(pkcs11.CKZ_DATA_SPECIFIED),
		ulongToBytes(0),
		ulongToBytes(0),
	)

	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, OEAPParams)}
	err = p.DecryptInit(s, mechanism, key.handle)
	if err != nil {
		return noBytes, fmt.Errorf("could not initialse decryption: %s", err)
	}

	plaintext, err := p.Decrypt(s, ciphertext)
	if err != nil {
		return noBytes, fmt.Errorf("could not decrypt: %s", err)
	}

	p.DecryptFinal(s)

	return plaintext, nil
}