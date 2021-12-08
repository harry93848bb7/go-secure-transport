package main

import (
	"fmt"
	"io"
	"net"
	"time"

	transport "github.com/harry93848bb7/go-secure-transport"
)

func main() {
	conn, err := net.DialTimeout("tcp", ":8484", 3*time.Second)
	if err != nil {
		panic(err)
	}
	defer func() {
		fmt.Println("closing dialer")
		conn.Close()
	}()
	tp := transport.NewTransport(true)

	pub, err := tp.PublicKey()
	if err != nil {
		panic(err)
	}
	fmt.Println("writing rsa public key to node")
	if _, err = conn.Write(pub); err != nil {
		panic(err)
	}
	go func() {
		for {
			time.Sleep(3 * time.Second)
			if tp.Secured() {
				payload, err := tp.Encrypt([]byte("hello from client"))
				_, err = conn.Write(payload)
				if err != nil {
					fmt.Println("failed to send encrypted payload to conn")
				}
			}
		}
	}()
	for {
		payload := make([]byte, 4096)
		n, err := io.ReadAtLeast(conn, payload, 1)
		if err != nil {
			fmt.Println("failed to read conn data: ", err.Error())
			return
		}
		if !tp.Secured() {
			err = tp.SecureInbound(payload[:n])
			if err != nil {
				fmt.Println("failed to secure conn: ", err.Error())
				return
			}
			fmt.Println("connection secured")
		} else {
			raw, err := tp.Decrypt(payload[:n])
			if err != nil {
				fmt.Println("decryption error: ", err.Error())
			}
			fmt.Println("message recieved from conn: " + string(raw))
		}
	}
}
