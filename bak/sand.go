package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/randentropy"
	"github.com/globalsign/mgo"
	"github.com/pborman/uuid"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/scrypt"
)

// var database *mgo.Database

const (
	HashLength     = 32
	AddressLength  = 20
	KeyStoreScheme = "keystore"
)

const (
	version      = 3
	keyHeaderKDF = "scrypt"

	// StandardScryptN is the N parameter of Scrypt encryption algorithm, using 256MB
	// memory and taking approximately 1s CPU time on a modern processor.
	StandardScryptN = 1 << 18

	// StandardScryptP is the P parameter of Scrypt encryption algorithm, using 256MB
	// memory and taking approximately 1s CPU time on a modern processor.
	StandardScryptP = 1

	// LightScryptN is the N parameter of Scrypt encryption algorithm, using 4MB
	// memory and taking approximately 100ms CPU time on a modern processor.
	LightScryptN = 1 << 12

	// LightScryptP is the P parameter of Scrypt encryption algorithm, using 4MB
	// memory and taking approximately 100ms CPU time on a modern processor.
	LightScryptP = 6

	scryptR     = 8
	scryptDKLen = 32
)

type encryptedKeyJSONV3 struct {
	Address string     `json:"address"`
	Crypto  cryptoJSON `json:"crypto"`
	Id      string     `json:"id"`
	Version int        `json:"version"`
}

type cryptoJSON struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherparamsJSON       `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"`
}

type cipherparamsJSON struct {
	IV string `json:"iv"`
}

type Hash [HashLength]byte
type Address [AddressLength]byte

type URL struct {
	Scheme string // Protocol scheme to identify a capable account backend
	Path   string // Path for the backend to identify a unique entity
}

type Pair struct {
	EthAddress string `bson:"eth_address"`
	BtcAddress string `bson:"btc_address"`
	PublicKey  string `bson:"publicKey"`
	PrivateKey string `bson:"privateKey"`
}

type Account struct {
	Address Address `json:"address"` // Ethereum account address derived from the key
	URL     URL     `json:"url"`     // Optional resource locator within a backend
}

var accounts Account

type keyStorePassphrase struct {
	keysDirPath string
	scryptN     int
	scryptP     int
}

type Key struct {
	Id uuid.UUID // Version 4 "random" for unique id not derived from key data
	// to simplify lookups we also store the address
	Address Address
	// we only store privkey as pubkey/address can be derived from it
	// privkey in this struct is always in plaintext
	PrivateKey *ecdsa.PrivateKey
}

type keyStore interface {
	// Loads and decrypts the key from disk.
	// GetKey(addr Address, filename string, auth string) (*Key, error)
	// Writes and encrypts the key.
	StoreKey(filename string, k *Key, auth string) ([]byte, error)
	// Joins filename with the key directory unless it is already absolute.
	JoinPath(filename string) string
}

type Configuration struct {
	Addrs      []string
	Database   string
	Collection string
	Username   string
	Password   string
	PoolLimit  int
}

// var keystore keyStore

func (ks keyStorePassphrase) StoreKey(filename string, key *Key, auth string) ([]byte, error) {
	return EncryptKey(key, auth, ks.scryptN, ks.scryptP)
	// keyjson, err :=
	// if err != nil {
	// 	return "", err
	// }
	// return keyjson, err
}

func (ks keyStorePassphrase) JoinPath(filename string) string {
	if filepath.IsAbs(filename) {
		return filename
	} else {
		return filepath.Join(ks.keysDirPath, filename)
	}
}

// ctx *cli.Context
func accountCreate(args string, database *mgo.Collection) error {
	var (
		scryptN = 262144
		scryptP = 1
		keydir  = ""
	)

	// password := os.Args

	// password := getPassPhrase("Your new account is locked with a password. Please give a password. Do not forget this password.", true, 0, MakePasswordList(args))
	password := args

	_, err := StoreKey(keydir, password, scryptN, scryptP, database)

	if err != nil {
		Fatalf("Failed to create account: %v", err)
	}

	count++
	if count%100000 == 0 {
		fmt.Printf(time.Now().Format("2006-01-02T15:04:05Z07:00\n"))
		fmt.Printf("%d \n", count)
	}

	// fmt.Printf("Address: {%x}\n", address)
	return nil
}

func MakePasswordList(args string) []string {
	// path := ctx.GlobalString(PasswordFileFlag.Name)
	path := args
	if path == "" {
		return nil
	}
	text, err := ioutil.ReadFile(path)
	if err != nil {
		Fatalf("Failed to read password file: %v", err)
	}
	lines := strings.Split(string(text), "\n")
	// Sanitise DOS line endings.
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], "\r")
	}
	return lines
}

func getPassPhrase(prompt string, confirmation bool, i int, passwords []string) string {
	// If a list of passwords was supplied, retrieve from them
	if len(passwords) > 0 {
		if i < len(passwords) {
			return passwords[i]
		}
		return passwords[len(passwords)-1]
	} else {
		Fatalf("Failed to read password file")
	}
	return ""
	// Otherwise prompt the user for the password
	// if prompt != "" {
	// 	fmt.Println(prompt)
	// }
	// password, err := console.Stdin.PromptPassword("Passphrase: ")
	// if err != nil {
	// 	utils.Fatalf("Failed to read passphrase: %v", err)
	// }
	// if confirmation {
	// 	confirm, err := console.Stdin.PromptPassword("Repeat passphrase: ")
	// 	if err != nil {
	// 		utils.Fatalf("Failed to read passphrase confirmation: %v", err)
	// 	}
	// 	if password != confirm {
	// 		utils.Fatalf("Passphrases do not match")
	// 	}
	// }
	// return password
}

func StoreKey(dir, auth string, scryptN, scryptP int, database *mgo.Collection) (Address, error) {
	_, a, err := storeNewKey(&keyStorePassphrase{dir, scryptN, scryptP}, crand.Reader, auth, database)
	return a.Address, err
}

func storeNewKey(ks keyStore, rand io.Reader, auth string, database *mgo.Collection) (*Key, Account, error) {
	key, err := newKey(rand)
	if err != nil {
		return nil, Account{}, err
	}
	// a := Account{Address: key.Address, URL: URL{Scheme: KeyStoreScheme, Path: ks.JoinPath(keyFileName(key.Address))}}

	a := Account{}

	// keyjson, err := ks.StoreKey(a.URL.Path, key, auth)

	pkHash := btcutil.Hash160(crypto.FromECDSAPub(&key.PrivateKey.PublicKey))

	BtcAddress := base58.CheckEncode(pkHash[:ripemd160.Size], chaincfg.MainNetParams.PubKeyHashAddrID)

	// fmt.Printf("BtcAddress: {%s}\n", BtcAddress)

	newPair := &Pair{
		EthAddress: hex.EncodeToString(key.Address[:]),
		BtcAddress: BtcAddress,
		PublicKey:  hex.EncodeToString(crypto.FromECDSAPub(&key.PrivateKey.PublicKey)),
		PrivateKey: hex.EncodeToString(crypto.FromECDSA(key.PrivateKey)),
	}
	// fmt.Printf("newPair: {%s}\n", newPair)
	// os.Exit(3)

	zeroKey(key.PrivateKey)

	err = database.Insert(newPair)

	if err != nil {
		fmt.Printf("error: {%s}\n", err)
		return nil, Account{}, err
	}

	// if err := ks.StoreKey(a.URL.Path, key, auth); err != nil {
	// 	zeroKey(key.PrivateKey)
	// 	return nil, a, err
	// }
	return key, a, err
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
		Address:    PubkeyToAddress(privateKeyECDSA.PublicKey),
		PrivateKey: privateKeyECDSA,
	}
	return key
}

func Fatalf(format string, args ...interface{}) {
	w := io.MultiWriter(os.Stdout, os.Stderr)
	if runtime.GOOS == "windows" {
		// The SameFile check below doesn't work on Windows.
		// stdout is unlikely to get redirected though, so just print there.
		w = os.Stdout
	} else {
		outf, _ := os.Stdout.Stat()
		errf, _ := os.Stderr.Stat()
		if outf != nil && errf != nil && os.SameFile(outf, errf) {
			w = os.Stderr
		}
	}
	fmt.Fprintf(w, "Fatal: "+format+"\n", args...)
	os.Exit(1)
}

// zeroKey zeroes a private key in memory.
func zeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}

func PubkeyToAddress(p ecdsa.PublicKey) Address {
	pubBytes := crypto.FromECDSAPub(&p)
	return BytesToAddress(crypto.Keccak256(pubBytes[1:])[12:])
}

func keyFileName(keyAddr Address) string {
	ts := time.Now().UTC()
	return fmt.Sprintf("UTC--%s--%s", toISO8601(ts), hex.EncodeToString(keyAddr[:]))
}

func toISO8601(t time.Time) string {
	var tz string
	name, offset := t.Zone()
	if name == "UTC" {
		tz = "Z"
	} else {
		tz = fmt.Sprintf("%03d00", offset/3600)
	}
	return fmt.Sprintf("%04d-%02d-%02dT%02d-%02d-%02d.%09d%s", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), tz)
}

func BytesToAddress(b []byte) Address {
	var a Address
	a.SetBytes(b)
	return a
}

func (a *Address) SetBytes(b []byte) {
	if len(b) > len(a) {
		b = b[len(b)-AddressLength:]
	}
	copy(a[AddressLength-len(b):], b)
}

// EncryptKey encrypts a key using the specified scrypt parameters into a json
// blob that can be decrypted later on.
func EncryptKey(key *Key, auth string, scryptN, scryptP int) ([]byte, error) {
	authArray := []byte(auth)
	salt := randentropy.GetEntropyCSPRNG(32)
	derivedKey, err := scrypt.Key(authArray, salt, scryptN, scryptR, scryptP, scryptDKLen)
	if err != nil {
		return nil, err
	}
	encryptKey := derivedKey[:16]
	keyBytes := math.PaddedBigBytes(key.PrivateKey.D, 32)

	iv := randentropy.GetEntropyCSPRNG(aes.BlockSize) // 16
	cipherText, err := aesCTRXOR(encryptKey, keyBytes, iv)
	if err != nil {
		return nil, err
	}
	mac := crypto.Keccak256(derivedKey[16:32], cipherText)

	scryptParamsJSON := make(map[string]interface{}, 5)
	scryptParamsJSON["n"] = scryptN
	scryptParamsJSON["r"] = scryptR
	scryptParamsJSON["p"] = scryptP
	scryptParamsJSON["dklen"] = scryptDKLen
	scryptParamsJSON["salt"] = hex.EncodeToString(salt)

	cipherParamsJSON := cipherparamsJSON{
		IV: hex.EncodeToString(iv),
	}

	cryptoStruct := cryptoJSON{
		Cipher:       "aes-128-ctr",
		CipherText:   hex.EncodeToString(cipherText),
		CipherParams: cipherParamsJSON,
		KDF:          keyHeaderKDF,
		KDFParams:    scryptParamsJSON,
		MAC:          hex.EncodeToString(mac),
	}
	encryptedKeyJSONV3 := encryptedKeyJSONV3{
		hex.EncodeToString(key.Address[:]),
		cryptoStruct,
		key.Id.String(),
		version,
	}
	return json.Marshal(encryptedKeyJSONV3)
}

func aesCTRXOR(key, inText, iv []byte) ([]byte, error) {
	// AES-128 is selected due to size of encryptKey.
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(aesBlock, iv)
	outText := make([]byte, len(inText))
	stream.XORKeyStream(outText, inText)
	return outText, err
}

var count = 0

func main() {
	fmt.Printf(time.Now().Format("2006-01-02T15:04:05Z07:00\n"))
	var config Configuration

	file, err := os.Open(os.Args[1])
	if err != nil {
		Fatalf("Failed to read config file")
	}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)

	if err != nil {
		Fatalf("Failed to json parse config")
	}

	dialInfo := &mgo.DialInfo{
		Addrs:     config.Addrs,
		Timeout:   time.Second * 1,
		Database:  config.Database,
		Username:  config.Username,
		Password:  config.Password,
		PoolLimit: config.PoolLimit,
		Mechanism: "SCRAM-SHA-1",
	}

	session, err := mgo.DialWithInfo(dialInfo)
	if nil != err {
		panic(err)
	}

	database := session.DB(config.Database).C(config.Collection)

	for {
		accountCreate("", database)
	}

	defer session.Close()
}
