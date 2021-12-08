package main

import (
	"fmt"
	"io"
	"net"
	"time"

	transport "github.com/harry93848bb7/go-secure-transport"
)

func main() {
	l, err := net.Listen("tcp", ":8484")
	if err != nil {
		panic(err)
	}
	fmt.Println("listening for new peers")
	for {
		peer, err := l.Accept()
		if err != nil {
			panic(err)
		}
		fmt.Println("accepted peer connection: ", peer.LocalAddr())
		go handlePeer(peer)
	}
}

func handlePeer(peer net.Conn) {
	defer func() {
		fmt.Println("closing peer connection...")
		peer.Close()
	}()
	tp := transport.NewTransport(false)
	go func() {
		for {
			time.Sleep(3 * time.Second)
			if tp.Secured() {
				payload, err := tp.Encrypt([]byte("hello from server"))
				_, err = peer.Write(payload)
				if err != nil {
					fmt.Println("failed to send encrypted payload to conn")
				}
			}
		}
	}()
	for {
		buff := make([]byte, 4096)
		n, err := io.ReadAtLeast(peer, buff, 1)
		if err != nil {
			fmt.Println("failed to read peer data: ", err.Error())
			return
		}
		if !tp.Secured() {
			resposne, err := tp.SecureOutbound(buff[:n])
			if err != nil {
				panic(err)
			}
			fmt.Println("sending encrypted session key to peer: ", peer.LocalAddr())
			_, err = peer.Write(resposne)
			if err != nil {
				fmt.Println("failed to write peer data: ", err.Error())
				return
			}
		} else {
			raw, err := tp.Decrypt(buff[:n])
			if err != nil {
				fmt.Println("decryption error: ", err.Error())
			}
			fmt.Println("message recieved from peer: " + string(raw))
		}
	}
}
