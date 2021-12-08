# go-secure-transport

WIP minimal implementation of secure encrypted TCP transport connection. See `./example` for server / client handshake implementation.

#### cryptography:
1. rsa 2096 public key encryption (paired with keccak256)
2. xchacha20poly1305 symmetric key encryption
