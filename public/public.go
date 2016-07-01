package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

var pubKeyFile = flag.String("pub", "", "public key file")
var data = flag.String("data", "", "data file")

func main() {

	flag.Parse()

	if *pubKeyFile == "" || *data == "" {
		fmt.Printf("Usage: public -pub PUBKEY_FILE -data DATA_FILE\n")
		os.Exit(5)
	}

	pkFile, ferr := os.Open(*pubKeyFile)

	if ferr != nil {
		fmt.Printf("Error: %v\n", ferr)
		os.Exit(6)
	}

	pubKey, rerr := ioutil.ReadAll(pkFile)

	if rerr != nil {
		fmt.Printf("Error: %v\n", rerr)
		os.Exit(7)
	}

	dataFile, derr := os.Open(*data)
	if derr != nil {
		fmt.Printf("Error: %v\n", derr)
		os.Exit(8)
	}

	message, merr := ioutil.ReadAll(dataFile)
	if merr != nil {
		fmt.Printf("Error: %v\n", merr)
		os.Exit(8)
	}

	block, rest := pem.Decode([]byte(pubKey))

	if len(rest) > 0 {
		fmt.Println("Error: what happend to the key!")
		os.Exit(1)
	}

	publicKeyI, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Printf("Error: failed to parse public key: %v\n", err)
		os.Exit(2)
	}
	publicKey, ok := publicKeyI.(*rsa.PublicKey)
	if !ok {
		fmt.Println("Error: not valid public key")
		os.Exit(3)
	}
	randR := rand.Reader
	plain := []byte(message)
	enc, eerr := rsa.EncryptPKCS1v15(randR, publicKey, plain)
	if eerr != nil {
		fmt.Printf("Error: failed to encrypt message(len: %d): %v\n", len(plain), eerr)
		fmt.Printf(`Note: RSAES-PKCS1-v1_5 can operate on messages of length up to k - 11 octets (k is the octet length of the RSA modulus)`)
		os.Exit(4)
	}

	encHex := hex.EncodeToString(enc)
	fmt.Printf(encHex)
}
