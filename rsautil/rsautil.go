package rsautil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// NewKey2048 will generate a new 2048 bit key for RSA
//
// 2048 bits is generally considered the best tradeoff between
// security and performance at the time of writing.  Probably
// this will remain the case until 2030.
func NewKey2048() (privateKey, publicKey []byte, err error) {
	return keyToPems(rsa.GenerateKey(rand.Reader, 2048))
}

// NewKey3072 will generate a new 3072 bit key for RSA.
//
// Use a 3072 bit key for extra performance, at the cost of performance.
func NewKey3072() (privateKey, publicKey []byte, err error) {
	return keyToPems(rsa.GenerateKey(rand.Reader, 3027))
}

// NewKey4096 will generate a new 4096 bit key for RSA
//
// Use a 4096 bit key maximum security, at the cost of performance.
func NewKey4096() (privateKey, publicKey []byte, err error) {
	return keyToPems(rsa.GenerateKey(rand.Reader, 4096))
}

func keyToPems(key *rsa.PrivateKey, keyErr error) (privateKey, publicKey []byte, err error) {
	if keyErr != nil {
		err = keyErr
		return
	}
	privateKey = PrivateKeyToPem(key)
	publicKey = PublicKeyToPem(&key.PublicKey)
	return
}

func PrivateKeyToPem(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)
}

func PublicKeyToPem(key *rsa.PublicKey) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(key),
		},
	)
}

func PemToPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	p, _ := pem.Decode(pemData)
	if p == nil {
		return nil, errors.New("invalid pem file")
	}
	return x509.ParsePKCS1PrivateKey(p.Bytes)
}

func PemToPublicKey(pemData []byte) (*rsa.PublicKey, error) {
	p, _ := pem.Decode(pemData)
	if p == nil {
		return nil, errors.New("invalid pem file")
	}
	return x509.ParsePKCS1PublicKey(p.Bytes)
}
