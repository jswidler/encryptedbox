package main

import (
	"fmt"

	"github.com/jswidler/encryptedbox"
	"github.com/jswidler/encryptedbox/aesutil"
)

func main() {
	// Generate a new AES-256 key
	key, err := aesutil.NewKey256()
	if err != nil {
		panic(err)
	}

	// Initialize the cipher
	cipher, err := encryptedbox.NewAESCipher(key)
	if err != nil {
		panic(err)
	}

	// Enable zlib compression.  The default uses zlib.BestCompression.
	cipher.Compressor = encryptedbox.Zlib
	// If you want to use a different level of compression, use the following:
	//cipher.Compressor = encryptedbox.ZlibCompression(zlib.BestSpeed)

	// We will use raw strings.  The default JSON Serializer would still work, but it
	// is less efficient since it will JSON encode the string.
	cipher.Serializer = encryptedbox.String

	// This sentence is probably more compressable than most.
	msg := "Buffalo buffalo Buffalo buffalo buffalo buffalo Buffalo buffalo."

	// Encrypt the message using compression
	compressedCiphertext, err := cipher.Encrypt(msg)
	if err != nil {
		panic(err)
	}
	compressedLen := len(compressedCiphertext)

	// Check the message can be decrypted
	var decrypted string
	err = cipher.Decrypt(compressedCiphertext, &decrypted)
	if err != nil {
		panic(err)
	}
	fmt.Printf("decrypted message: %+v\n", decrypted)

	// For comparison, turn off compression and encrypt the same message again.
	cipher.Compressor = nil
	uncompressedCiphertext, err := cipher.Encrypt(msg)
	if err != nil {
		panic(err)
	}
	uncompressedLen := len(uncompressedCiphertext)
	bytesSaved := uncompressedLen - compressedLen
	percentSaved := 100 * bytesSaved / uncompressedLen

	fmt.Printf("compressed ciphertext length: %d\n", compressedLen)
	fmt.Printf("uncompressed ciphertext length: %d\n", uncompressedLen)
	if bytesSaved >= 0 {
		fmt.Printf("using compression saved %d bytes (%d%%)\n", bytesSaved, percentSaved)
	} else {
		fmt.Printf("using compression wasted %d bytes (%d%%)\n", -bytesSaved, -percentSaved)
	}
}
