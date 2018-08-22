package main

import (
	"fmt"
	"time"
	"io"
	"./crypto"
	"crypto/ecdsa"
	crand "crypto/rand"
)

type Key struct {
	// Id uuid.UUID // Version 4 "random" for unique id not derived from key data
	// to simplify lookups we also store the address
	// Address Address
	// we only store privkey as pubkey/address can be derived from it
	// privkey in this struct is always in plaintext
	PrivateKey *ecdsa.PrivateKey
}

func newKey(rand io.Reader) (*Key, error) {
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand)

	if err != nil {
		return nil, err
	}

	return newKeyFromECDSA(privateKeyECDSA), nil
}

func newKeyFromECDSA(privateKeyECDSA *ecdsa.PrivateKey) *Key {
	key := &Key{
		// Address:    PubkeyToAddress(privateKeyECDSA.PublicKey),
		PrivateKey: privateKeyECDSA,
	}
	return key
}

func main() {
	fmt.Printf(time.Now().Format("2006-01-02T15:04:05Z07:00\n"))

	key, err := newKey(crand.Reader)
	if err != nil {
		return
	}

	fmt.Printf("key: {%s}\n", key)
}