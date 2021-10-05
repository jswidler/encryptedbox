package encryptedbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/jswidler/encryptedbox/rsautil"
)

// AES will return a symmetric Encrypter using AES
func AES(key []byte) (Encrypter, error) {
	l := len(key)
	if l != 32 && l != 24 && l != 16 {
		return nil, errors.New("AES keys must be 16, 24, or 32 bytes")
	}
	return &aesEnc{key}, nil
}

// RSA will return an asymmetric Encrypter using RSA
func RSA(privateKeyPem []byte) (Encrypter, error) {
	key, err := rsautil.PemToPrivateKey(privateKeyPem)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA private key: %w", err)
	}
	return rsaEnc{privateKey: key, publicKey: &key.PublicKey}, nil
}

// RSAEncryptOnly will return an asymmetric Encrypter using RSA
// which can only Encrypt.
func RSAEncryptOnly(publicKeyPem []byte) (Encrypter, error) {
	key, err := rsautil.PemToPublicKey(publicKeyPem)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA public key: %w", err)
	}
	return rsaEnc{publicKey: key}, nil
}

type aesEnc struct {
	key []byte
}

func (a aesEnc) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nonce[:], nonce[:], plaintext, nil), nil
}

func (a aesEnc) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("invalid ciphertext")
	}
	return aead.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
}

type rsaEnc struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func (r rsaEnc) Encrypt(plaintext []byte) ([]byte, error) {
	return encryptOAEPChunks(sha512.New(), rand.Reader, r.publicKey, plaintext, nil)
}

func (r rsaEnc) Decrypt(ciphertext []byte) ([]byte, error) {
	return decryptOAEPChunks(sha512.New(), nil, r.privateKey, ciphertext, nil)
}

func encryptOAEPChunks(hash hash.Hash, random io.Reader, public *rsa.PublicKey, msg []byte, label []byte) ([]byte, error) {
	msgLen := len(msg)
	step := public.Size() - 2*hash.Size() - 2
	var encryptedBytes []byte
	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}
		encryptedBlockBytes, err := rsa.EncryptOAEP(hash, random, public, msg[start:finish], label)
		if err != nil {
			return nil, err
		}
		encryptedBytes = append(encryptedBytes, encryptedBlockBytes...)
	}
	return encryptedBytes, nil
}

func decryptOAEPChunks(hash hash.Hash, random io.Reader, private *rsa.PrivateKey, msg []byte, label []byte) ([]byte, error) {
	msgLen := len(msg)
	step := private.PublicKey.Size()
	var decryptedBytes []byte
	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}
		decryptedBlockBytes, err := rsa.DecryptOAEP(hash, random, private, msg[start:finish], label)
		if err != nil {
			return nil, err
		}

		decryptedBytes = append(decryptedBytes, decryptedBlockBytes...)
	}
	return decryptedBytes, nil
}
