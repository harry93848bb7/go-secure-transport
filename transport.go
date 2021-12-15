package transport

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

func OutboundHandshake(conn net.Conn, timeout time.Duration) (cipher.AEAD, error) {
	deadline := time.Now().Add(timeout)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	if err = conn.SetWriteDeadline(deadline); err != nil {
		return nil, err
	}
	n, err := conn.Write(x509.MarshalPKCS1PublicKey(&key.PublicKey))
	if err != nil {
		return nil, err
	}
	if n != 270 {
		return nil, errors.New("failed to write pubic key to conn")
	}
	if err = conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	response := make([]byte, 256)
	n, err = io.ReadFull(conn, response)
	if err != nil {
		return nil, err
	}
	if n != 256 {
		return nil, errors.New("failed to read entire handshake response")
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	session, err := rsa.DecryptOAEP(sha3.NewLegacyKeccak256(), rand.Reader, key, response, nil)
	if err != nil {
		return nil, err
	}
	if len(session) != 32 {
		return nil, errors.New("bad symmetric key length")
	}
	aead, err := chacha20poly1305.NewX(session)
	if err != nil {
		return nil, err
	}
	return aead, nil
}

func InboundHandshake(conn net.Conn, timeout time.Duration) (cipher.AEAD, error) {
	deadline := time.Now().Add(timeout)

	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	request := make([]byte, 270)
	n, err := io.ReadFull(conn, request)
	if err != nil {
		return nil, err
	}
	if n != 270 {
		return nil, errors.New("failed to read entire handshake request")
	}
	pub, err := x509.ParsePKCS1PublicKey(request)
	if err != nil {
		return nil, err
	}
	if pub.Size() != 256 {
		return nil, errors.New("bad rsa key size")
	}
	session := make([]byte, 32)
	if _, err := rand.Read(session); err != nil {
		return nil, err
	}
	response, err := rsa.EncryptOAEP(sha3.NewLegacyKeccak256(), rand.Reader, pub, session, nil)
	if err != nil {
		return nil, err
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return nil, err
	}
	n, err = conn.Write(response)
	if err != nil {
		return nil, err
	}
	if n != 256 {
		return nil, errors.New("failed to write entire handshake response")
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(session)
	if err != nil {
		return nil, err
	}
	return aead, nil
}
