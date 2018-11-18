package main

import (
	"fmt"
	"time"
	"io"
	"./crypto"
	"./address"
	"crypto/ecdsa"
	crand "crypto/rand"
)

type Pair struct {
	EthAddress string `bson:"eth_address"`
	BtcAddress string `bson:"btc_address"`
	PublicKey  string `bson:"publicKey"`
	PrivateKey string `bson:"privateKey"`
}

func newKey(rand io.Reader) (*Pair, error) {
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand)

	if err != nil { return nil, err }

	return newKeyFromECDSA(privateKeyECDSA), nil
}

func newKeyFromECDSA(privateKeyECDSA *ecdsa.PrivateKey) *Pair {
	pair := &Pair{
		PrivateKey: address.EncodeToPrivateKey(privateKeyECDSA),
		PublicKey:  address.EncodeToPublicKey(privateKeyECDSA),
		BtcAddress: address.EncodeToBitcoin(privateKeyECDSA),
		EthAddress: address.EncodeToEthereum(privateKeyECDSA),
	}
	return pair
}

var count = 0
var now = time.Now()
func main() {

	fmt.Printf(now.Format("2006-01-02T15:04:05Z07:00\n"))


	for {
		_, err := newKey(crand.Reader)
		if err != nil { fmt.Errorf("%v", err) }
		count ++

		if time.Now().Second() > now.Second() {
			fmt.Println(now.Second(), "now")
			fmt.Println(time.Now().Second(), "Now")
			fmt.Println(count, "这是")
			break
		}
	}



	// if err != nil { fmt.Errorf("%v", err) }

	//fmt.Printf("%+v\n", pair)
}