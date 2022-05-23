package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"github.com/siler23/tezos-key-encoder/encoder"
)

func fileExists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		return os.IsExist(err)
	}
	return true
}

func main() {
	if len(os.Args) < 2 || !fileExists(os.Args[1]) {
		log.Fatal("Usage: encoder <key>.pem")
	}

	fileName := os.Args[1]
	log.Println("Parsing: ", fileName)

	pemBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Fatal("Could not read file: ", fileName, err)
	}

	tz := encoder.GetTezosKeys(pemBytes)
	fmt.Println("Curve: ", tz.Curve)
	fmt.Println("Tezos Secret Key: ", tz.SecretKey)
	fmt.Println("Tezos Public Key: ", tz.PublicKey)
	fmt.Println("Tezos Public Key Hash: ", tz.PublicKeyHash)
}
