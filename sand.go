package main

import (
	"fmt"
	"time"
	"io"
	"./crypto"
	"./address"
	"crypto/ecdsa"
	crand "crypto/rand"

	"database/sql"

	_ "github.com/lib/pq"
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
		// PublicKey:  address.EncodeToPublicKey(privateKeyECDSA),
		BtcAddress: address.EncodeToBitcoin(privateKeyECDSA),
		EthAddress: address.EncodeToEthereum(privateKeyECDSA),
	}
	return pair
}

var count = 0
var now = time.Now()

func test() {
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
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

const (
	host = "localhost"
	port = 5432
	user = "postgres"
	dbname=""
)


func main() {
	fmt.Printf(now.Format("2006-01-02T15:04:05Z07:00\n"))
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=disable",host,port,user,dbname)
	db, err := sql.Open("postgres", psqlInfo)
	checkErr(err)
	defer db.Close()

	for {
		pair, err := newKey(crand.Reader)
		checkErr(err)
		stmt, err := db.Prepare("INSERT INTO sand(private_key,btc_address,eth_address) VALUES($1,$2,$3)")
		checkErr(err)
		_, err = stmt.Exec(pair.PrivateKey, pair.BtcAddress, pair.EthAddress)
		checkErr(err)
		break

		//count ++

		//time.Now().Minute()
		//if time.Now().Second() > now.Second() {
		//	fmt.Println(now.Second(), "now")
		//	fmt.Println(time.Now().Second(), "Now")
		//	fmt.Println(count, "这是")
		//	break
		//}
	}



	// if err != nil { fmt.Errorf("%v", err) }

	//fmt.Printf("%+v\n", pair)
}