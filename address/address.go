package address

import (
	"crypto/ecdsa"
	"encoding/hex"
	"crypto/sha256"
	"hash"
	"../crypto"

	"../crypto/ripemd160"
	"math/big"
)

const Ripemd160Size = 20

const (
	PubKeyHashAddrID        = 0x00 // starts with 1
	ScriptHashAddrID        = 0x05 // starts with 3
	PrivateKeyID            = 0x80 // starts with 5 (uncompressed) or K (compressed)
	WitnessPubKeyHashAddrID = 0x06 // starts with p2
	WitnessScriptHashAddrID = 0x0A // starts with 7Xh
)

func EncodeToPrivateKey(priv *ecdsa.PrivateKey) string {
	return hex.EncodeToString(crypto.FromECDSA(priv))
}

func EncodeToPublicKey(priv *ecdsa.PrivateKey) string {
	return hex.EncodeToString(crypto.FromECDSAPub(&priv.PublicKey))
}

func EncodeToBitcoin(priv *ecdsa.PrivateKey) string {
	pkHash := Hash160(crypto.FromECDSAPub(&priv.PublicKey))

	return CheckEncode(pkHash[:ripemd160.Size], PubKeyHashAddrID)
}

func EncodeToEthereum(priv *ecdsa.PrivateKey) string {
	addr := crypto.PubkeyToAddress(priv.PublicKey)
	return hex.EncodeToString(addr[:])
}

// Calculate the hash of hasher over buf.
func calcHash(buf []byte, hasher hash.Hash) []byte {
	hasher.Write(buf)
	return hasher.Sum(nil)
}

// Hash160 calculates the hash ripemd160(sha256(b)).
func Hash160(buf []byte) []byte {
	return calcHash(calcHash(buf, sha256.New()), ripemd160.New())
}

// checksum: first four bytes of sha256^2
func checksum(input []byte) (cksum [4]byte) {
	h := sha256.Sum256(input)
	h2 := sha256.Sum256(h[:])
	copy(cksum[:], h2[:4])
	return
}

// CheckEncode prepends a version byte and appends a four byte checksum.
func CheckEncode(input []byte, version byte) string {
	b := make([]byte, 0, 1+len(input)+4)
	b = append(b, version)
	b = append(b, input[:]...)
	cksum := checksum(b)
	b = append(b, cksum[:]...)
	return Encode(b)
}

var bigRadix = big.NewInt(58)
var bigZero = big.NewInt(0)

const (
	// alphabet is the modified base58 alphabet used by Bitcoin.
	alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	alphabetIdx0 = '1'
)

// Encode encodes a byte slice to a modified base58 string.
func Encode(b []byte) string {
	x := new(big.Int)
	x.SetBytes(b)

	answer := make([]byte, 0, len(b)*136/100)
	for x.Cmp(bigZero) > 0 {
		mod := new(big.Int)
		x.DivMod(x, bigRadix, mod)
		answer = append(answer, alphabet[mod.Int64()])
	}

	// leading zero bytes
	for _, i := range b {
		if i != 0 {
			break
		}
		answer = append(answer, alphabetIdx0)
	}

	// reverse
	alen := len(answer)
	for i := 0; i < alen/2; i++ {
		answer[i], answer[alen-1-i] = answer[alen-1-i], answer[i]
	}

	return string(answer)
}
