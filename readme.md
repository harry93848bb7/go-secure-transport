# go-secure-transport

Demo implementation of secured encrypted TCP connection without TLS / SSL. See `./example` for server & client using the transport type.

### Flow
The goal is to exchange a symmetric key between 2 parties by using asymmetric public-key cryptography. Once the key is exchanged we can now use the symmetric key to bidirectionally encrypt / decrypt traffic.

1. Bob dials Alice and writes his RSA PublicKey to Alice.
2. Alice generates a symmetric key, encrypts it with Bob's PublicKey.
3. Alice sends the encrypted symmetric key to Bob.
4. Bob decrypted the payload with his RSA PrivateKey.

### Crypgraphy
- OAEP RSA (2048 bit key) + Keccak256
- XChaCha20-Poly1305 AEAD (256 bit key)
