package main

import (
	"fmt"

	"github.com/jswidler/encryptedbox"
	"github.com/jswidler/encryptedbox/rsautil"
)

type Data struct {
	Greeting string
	Pi       float32
}

func main() {
	privateKey, _, err := rsautil.NewKey2048()
	if err != nil {
		panic(err)
	}
	cipher, err := encryptedbox.NewRSACipher(privateKey)
	if err != nil {
		panic(err)
	}

	myData := Data{
		Greeting: "Hello world!",
		Pi:       3.1415927,
	}

	ciphertext, err := cipher.EncryptToString(myData)
	if err != nil {
		panic(err)
	}

	var decrypted Data
	err = cipher.DecryptString(ciphertext, &decrypted)
	if err != nil {
		panic(err)
	}

	fmt.Printf("ciphertext: %s\n", ciphertext)
	fmt.Printf("decrypted: %+v\n", decrypted)
}
