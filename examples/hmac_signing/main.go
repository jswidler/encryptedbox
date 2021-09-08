package main

import (
	"fmt"

	"github.com/jswidler/encryptedbox"
	"github.com/jswidler/encryptedbox/aesutil"
)

type Data struct {
	Greeting string
	Pi       float32
}

type DataV2 struct {
	Greeting         string
	Pi               float32
	NewOptionalField string
}

func main() {
	key, err := aesutil.NewKey256()
	if err != nil {
		panic(err)
	}
	signer, err := encryptedbox.NewHMACSHA256Signer(key)
	if err != nil {
		panic(err)
	}

	myData := Data{
		Greeting: "Hello world!",
		Pi:       3.1415927,
	}

	sig, serializedData, err := signer.Sign(myData)
	if err != nil {
		panic(err)
	}

	// If you are able to reproduce the original data structure in a way that will be serialized
	// exactly the same as the first time, you can verify against that.
	err = signer.Verify(myData, sig)
	if err != nil {
		panic(err)
	}

	// To avoid breaking signatures across versions, it might be required to use
	// the exact form that was signed, in which case a deserialized version can be produced.
	// This assumes the
	deserialized := DataV2{}
	err = signer.VerifyAndLoad(serializedData, sig, &deserialized)
	if err != nil {
		panic(err)
	}

	// Because we serialized to json, we can read the raw bytes as a string.
	fmt.Printf("signed bytes: %+v\n", string(serializedData))
	fmt.Printf("signature: %s\n", sig)
}
