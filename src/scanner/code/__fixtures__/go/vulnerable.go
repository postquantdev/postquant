package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/ed25519"
	"golang.org/x/crypto/curve25519"
)

func main() {
	// RSA key generation (CRITICAL)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_ = rsaKey

	// ECDSA key generation (CRITICAL)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_ = ecKey

	// Ed25519 (CRITICAL)
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = edPriv

	// X25519 (CRITICAL)
	var scalar, point [32]byte
	curve25519.ScalarMult(&scalar, &scalar, &point)

	// MD5 (CRITICAL)
	h := md5.New()
	_ = h

	// SHA-1 (CRITICAL)
	h1 := sha1.New()
	_ = h1
}
