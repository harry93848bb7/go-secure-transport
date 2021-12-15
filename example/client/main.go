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

var msg = []byte("hello from client!")

func main() {
	conn, err := net.DialTimeout("tcp", ":8484", 3*time.Second)
	if err != nil {
		panic(err)
	}
	defer func() {
		log.Println("closing outgoing connection")
		conn.Close()
	}()
	key, err := transport.OutboundHandshake(conn, 3*time.Second)
	if err != nil {
		log.Println("failed to secure outgoing connection: ", err.Error())
		return
	}
	log.Println("outgoing connection secured: ", conn.RemoteAddr())

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
			n, err := conn.Write(append(h, encryptedMsg...))
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
		n, err := io.ReadAtLeast(conn, header, 4)
		if err != nil {
			log.Println("failed to read outgoing conn: ", err)
			return
		}
		if n != 4 {
			log.Println("failed to read conn header: ", conn.RemoteAddr())
			return
		}
		size := binary.BigEndian.Uint32(header)
		sizei := int(size)
		if sizei < 24 || sizei > 32000000 {
			log.Println("bad packet size: ", conn.RemoteAddr())
			return
		}
		encrypted := make([]byte, sizei)
		n, err = io.ReadAtLeast(conn, encrypted, sizei)
		if err != nil {
			log.Println("failed to read outgoing conn: ", err)
			return
		}
		if n != sizei {
			log.Println("bad packet size: ", conn.RemoteAddr())
			return
		}
		nonce, ciphertext := encrypted[:24], encrypted[24:]
		plaintext, err := key.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			log.Println("failed to decrypt outgoing message: ", err)
			return
		}
		log.Println("message from outgoing conn: ", string(plaintext))
	}
}
