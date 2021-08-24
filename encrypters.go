package encryptedbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
)

func AES(key []byte) Encrypter {
	return &aesEnc{key}
}

func RSA(key *rsa.PrivateKey) Encrypter {
	return rsaEnc{privateKey: key, publicKey: &key.PublicKey}
}

func RSAEncryptOnly(key *rsa.PublicKey) Encrypter {
	return rsaEnc{publicKey: key}
}

func GenerateAESKey() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}

func GenerateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

type aesEnc struct {
	key []byte
}

func (a aesEnc) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, fmt.Errorf("failed to init aes cipher: %v", err)
	}
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, fmt.Errorf("failed to create aes initialization vector: %v", err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext, nil
}

func (a aesEnc) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, fmt.Errorf("failed to init aes cipher: %v", err)
	} else if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
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
