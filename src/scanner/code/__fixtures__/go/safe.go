package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"golang.org/x/crypto/chacha20poly1305"
)

func main() {
	// SHA-256 (SAFE)
	h := sha256.New()
	_ = h

	// SHA-512 (SAFE)
	h2 := sha512.New()
	_ = h2

	// ChaCha20-Poly1305 (SAFE)
	aead, _ := chacha20poly1305.New(make([]byte, 32))
	_ = aead
}
