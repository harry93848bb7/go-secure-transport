package main

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"log"
	"net"
	"time"

	transport "github.com/harry93848bb7/go-secure-transport"
)

var msg = []byte("hello from server!")

func main() {
	l, err := net.Listen("tcp", ":8484")
	if err != nil {
		panic(err)
	}
	log.Println("listening for new peers")
	for {
		peer, err := l.Accept()
		if err != nil {
			panic(err)
		}
		log.Println("accepted peer connection: ", peer.RemoteAddr())
		go handlePeer(peer)
	}
}

func handlePeer(peer net.Conn) {
	defer func() {
		log.Println("closing peer connection: ", peer.RemoteAddr())
		peer.Close()
	}()
	key, err := transport.InboundHandshake(peer, 3*time.Second)
	if err != nil {
		log.Println("failed to secure peer connection: ", err.Error())
		return
	}
	log.Println("peer connection secured: ", peer.RemoteAddr())

	go func() {
		for {
			time.Sleep(3 * time.Second)
			nonce := make([]byte, key.NonceSize(), key.NonceSize()+len(msg)+key.Overhead())
			if _, err := rand.Read(nonce); err != nil {
				panic(err)
			}
			encryptedMsg := key.Seal(nonce, nonce, msg, nil)
			h := make([]byte, 4)
			binary.BigEndian.PutUint32(h, uint32(len(encryptedMsg)))
			n, err := peer.Write(append(h, encryptedMsg...))
			if err != nil {
				panic(err)
			}
			if n != len(encryptedMsg)+4 {
				panic("failed to write entire payload")
			}
		}
	}()

	for {
		header := make([]byte, 4)
		n, err := io.ReadAtLeast(peer, header, 4)
		if err != nil {
			log.Println("failed to read peer: ", err)
			return
		}
		if n != 4 {
			log.Println("failed to read peer header: ", peer.RemoteAddr())
			return
		}
		size := binary.BigEndian.Uint32(header)
		sizei := int(size)
		if sizei < 24 || sizei > 32000000 {
			log.Println("bad packet size: ", peer.RemoteAddr())
			return
		}
		encrypted := make([]byte, sizei)
		n, err = io.ReadAtLeast(peer, encrypted, sizei)
		if err != nil {
			log.Println("failed to read peer: ", err)
			return
		}
		if n != sizei {
			log.Println("bad packet size: ", peer.RemoteAddr())
			return
		}
		nonce, ciphertext := encrypted[:24], encrypted[24:]
		plaintext, err := key.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			log.Println("failed to decrypt peer message: ", err)
			return
		}
		log.Println("message from peer: ", string(plaintext))
	}
}
