package crypto

import (
	"crypto/elliptic"
	"./secp256k1"
)

func S256() elliptic.Curve {
	return secp256k1.S256()
}