package encryptedbox

import (
	"crypto/rsa"
	"encoding/base64"
)

// A Packer produces encrypted messages, and
type Cipher struct {
	Serializer    Serializer
	Compressor    Compressor
	Encrypter     Encrypter
	StringEncoder StringEncoder
}

func AESCipher(aesKey []byte) *Cipher {
	return &Cipher{
		Serializer:    JSON,
		Compressor:    Zlib,
		Encrypter:     AES(aesKey),
		StringEncoder: base64.RawURLEncoding,
	}
}

func RSACipher(rsaKey *rsa.PrivateKey) *Cipher {
	return &Cipher{
		Serializer:    JSON,
		Compressor:    Zlib,
		Encrypter:     RSA(rsaKey),
		StringEncoder: base64.RawURLEncoding,
	}
}

func (c Cipher) Encrypt(data interface{}) ([]byte, error) {
	temp, err := c.Serializer.Serialize(data)
	if err != nil {
		return nil, err
	}
	if c.Compressor != nil {
		temp, err = c.Compressor.Compress(temp)
		if err != nil {
			return nil, err
		}
	}
	return c.Encrypter.Encrypt(temp)
}

func (c Cipher) Decrypt(ciphertext []byte, dst interface{}) error {
	temp, err := c.Encrypter.Decrypt(ciphertext)
	if err != nil {
		return err
	}
	if c.Compressor != nil {
		temp, err = c.Compressor.Decompress(temp)
		if err != nil {
			return err
		}
	}
	return c.Serializer.Deserialize(temp, dst)
}

func (c Cipher) EncryptToString(data interface{}) (string, error) {
	ciphertext, err := c.Encrypt(data)
	if err != nil {
		return "", err
	}
	return c.StringEncoder.EncodeToString(ciphertext), nil
}

func (c Cipher) DecryptString(ciphertext string, dst interface{}) error {
	b, err := c.StringEncoder.DecodeString(ciphertext)
	if err != nil {
		return err
	}
	return c.Decrypt(b, dst)
}
