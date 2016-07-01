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
	"strings"
)

var pkFile = flag.String("pk", "", "private key pem file")
var cipherFile = flag.String("cipher", "", "cipher data file")
var pkcs = flag.Int("pkcs", 8, "1: PKCS#1; 8: PKCS#8(Default)")

func main() {
	flag.Parse()

	if *pkFile == "" || *cipherFile == "" {
		fmt.Println("Usage: private -pk RSA_PRIVATE_PEM -cihper CIPHER_DATA_FILE")
		os.Exit(7)
	}

	pkf, _ := os.Open(*pkFile)
	pKeyPem, _ := ioutil.ReadAll(pkf)

	cf, _ := os.Open(*cipherFile)
	cipher, _ := ioutil.ReadAll(cf)
	cipherText := strings.Trim(string(cipher), "\n")

	cipherData, err1 := hex.DecodeString(cipherText)

	if err1 != nil {
		fmt.Printf("Error: %v\n", err1)
		os.Exit(3)
	}

	block, rest := pem.Decode([]byte(pKeyPem))

	if len(rest) > 0 {
		fmt.Println("Error: what happend to the key!")
		os.Exit(1)
	}

	var pKey *rsa.PrivateKey
	var err error

	if *pkcs == 1 {
		pKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else {
		var pKeyI interface{}
		pKeyI, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			fmt.Println("Error: faield to parse Private key")
			os.Exit(4)
		}

		var ok bool
		pKey, ok = pKeyI.(*rsa.PrivateKey)
		if !ok {
			os.Exit(5)
		}
	}

	randR := rand.Reader

	plain, err2 := rsa.DecryptPKCS1v15(randR, pKey, cipherData)
	if err2 != nil {
		fmt.Printf("Error: %v\n", err2)
		os.Exit(2)
	}
	fmt.Printf(string(plain))
}
