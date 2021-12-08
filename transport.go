package transport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

type Transport struct {
	secured     bool
	session     []byte
	outbound    bool
	outboundKey *rsa.PrivateKey
}

func NewTransport(outbound bool) *Transport {
	transport := &Transport{
		secured:  false,
		outbound: outbound,
	}
	if outbound {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		transport.outboundKey = key
	}
	return transport
}

func (t *Transport) PublicKey() ([]byte, error) {
	if !t.outbound {
		return nil, fmt.Errorf("invalid transport bound")
	}
	return x509.MarshalPKCS1PublicKey(&t.outboundKey.PublicKey), nil
}

func (t *Transport) SecureInbound(payload []byte) error {
	if !t.outbound {
		return fmt.Errorf("invalid transport bound")
	}
	session, err := rsa.DecryptOAEP(sha3.NewLegacyKeccak256(), rand.Reader, t.outboundKey, payload, nil)
	if err != nil {
		return err
	}
	if len(session) != 32 {
		return fmt.Errorf("bad symmetric key length")
	}
	t.session = session
	t.secured = true
	return nil
}

func (t *Transport) SecureOutbound(payload []byte) ([]byte, error) {
	pub, err := x509.ParsePKCS1PublicKey(payload)
	if err != nil {
		return nil, err
	}
	if pub.Size() != 256 {
		return nil, fmt.Errorf("bad rsa key size")
	}
	session := make([]byte, 32)
	if _, err := rand.Read(session); err != nil {
		return nil, err
	}
	response, err := rsa.EncryptOAEP(sha3.NewLegacyKeccak256(), rand.Reader, pub, session, nil)
	if err != nil {
		return nil, err
	}
	t.session = session
	t.secured = true
	return response, nil
}

func (t *Transport) Encrypt(payload []byte) ([]byte, error) {
	if !t.secured {
		return nil, fmt.Errorf("connection transport has not been secured")
	}
	aead, err := chacha20poly1305.NewX(t.session)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(payload)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, payload, nil), nil
}

func (t *Transport) Decrypt(payload []byte) ([]byte, error) {
	if !t.secured {
		return nil, fmt.Errorf("connection transport has not been secured")
	}
	aead, err := chacha20poly1305.NewX(t.session)
	if err != nil {
		return nil, err
	}
	if len(payload) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := payload[:aead.NonceSize()], payload[aead.NonceSize():]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (t *Transport) Secured() bool {
	return t.secured
}
