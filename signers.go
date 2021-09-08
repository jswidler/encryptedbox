package encryptedbox

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/jswidler/encryptedbox/rsautil"
)

// HMACSHA256 will return a Signer which uses HMAC-SHA-256
func HMACSHA256(key []byte) (Signer, error) {
	return &hmacSha256{key}, nil
}

// RSA will return an asymmetric Signer using RSA
func RSASigner(privateKeyPem []byte) (Signer, error) {
	key, err := rsautil.PemToPrivateKey(privateKeyPem)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA private key: %w", err)
	}
	return rsaEnc{privateKey: key, publicKey: &key.PublicKey}, nil
}

// RSAVerifyOnly will return an asymmetric Encrypter using RSA
// which can only Verify, but not sign.
func RSAVerifyOnly(publicKeyPem []byte) (Signer, error) {
	key, err := rsautil.PemToPublicKey(publicKeyPem)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA public key: %w", err)
	}
	return rsaEnc{publicKey: key}, nil
}

type hmacSha256 struct {
	key []byte
}

func (s hmacSha256) Sign(plaintext []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, s.key)
	mac.Write(plaintext)
	return mac.Sum(nil), nil
}

func (s hmacSha256) Verify(plaintext []byte, signature []byte) error {
	mac, _ := s.Sign(plaintext)
	if hmac.Equal(signature, mac) {
		return nil
	}
	return errors.New("invalid signature")
}

func (r rsaEnc) Sign(plaintext []byte) ([]byte, error) {
	msgHash := sha256.New()
	_, err := msgHash.Write(plaintext)
	if err != nil {
		return nil, err
	}
	msgHashSum := msgHash.Sum(nil)
	return rsa.SignPSS(rand.Reader, r.privateKey, crypto.SHA256, msgHashSum, nil)
}

func (r rsaEnc) Verify(plaintext []byte, signature []byte) error {
	msgHash := sha256.New()
	_, err := msgHash.Write(plaintext)
	if err != nil {
		return err
	}
	msgHashSum := msgHash.Sum(nil)
	return rsa.VerifyPSS(r.publicKey, crypto.SHA256, msgHashSum, signature, nil)
}
