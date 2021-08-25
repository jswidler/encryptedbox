package aesutil

import "crypto/rand"

// GenerateAESKey will generate a new 32 byte key for AES-256
//
// This is the recommended key size to use unless you have a reason to be extra
// concerned about performance and are willing to sacrafice some security peace
// of mind for it.
func NewKey256() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}

// GenerateAESKey will generate a new 32 byte key for AES-192
//
// AES-191 is probably secure and will be better performant than 256, but
// AES-256 is recommended anyway.
func NewKey192() ([]byte, error) {
	b := make([]byte, 24)
	_, err := rand.Read(b)
	return b, err
}

// GenerateAESKey will generate a new 32 byte key for AES-128
//
// AES-128 is probably secure and will be better performant than 256, but
// AES-256 is recommended anyway.
func NewKey128() ([]byte, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	return b, err
}
