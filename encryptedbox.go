package encryptedbox

import (
	"encoding/base64"
)

type Cipher struct {
	// Serializer performs the first (or final) step of converting the input data to a []byte
	Serializer Serializer

	// Compressor is an optional component to compress the output (or input) of the Serializer.
	Compressor Compressor

	// Encrypter controls the encryption and decryption steps.
	Encrypter Encrypter

	// StringEncoder must implement the StringEncoder interface
	//
	// It is suggested to use base64.RawURLEncoding.
	//
	// There are many Encodings from "encoding/base32", "encoding/base64",
	// and "encoding/hex" which satisfy the StringEncoder interface
	StringEncoder StringEncoder
}

// DefaultStringEncoder is the default encoder to use for Cipher.EncryptToString()
// and Cipher.DecryptString().
//
// This value is filled into the Cipher struct by the NewXXXCipher functions.
var DefaultStringEncoder StringEncoder = base64.RawURLEncoding

func NewAESCipher(aesKey []byte) (*Cipher, error) {
	encrypter, err := AES(aesKey)
	if err != nil {
		return nil, err
	}
	return &Cipher{
		Serializer:    JSON,
		Encrypter:     encrypter,
		StringEncoder: DefaultStringEncoder,
	}, nil
}

func NewRSACipher(privateKeyPem []byte) (*Cipher, error) {
	encrypter, err := RSA(privateKeyPem)
	if err != nil {
		return nil, err
	}
	return &Cipher{
		Serializer:    JSON,
		Encrypter:     encrypter,
		StringEncoder: DefaultStringEncoder,
	}, nil
}

func NewRSAEncryptOnlyCipher(publicKeypem []byte) (*Cipher, error) {
	encrypter, err := RSAEncryptOnly(publicKeypem)
	if err != nil {
		return nil, err
	}
	return &Cipher{
		Serializer:    JSON,
		Encrypter:     encrypter,
		StringEncoder: DefaultStringEncoder,
	}, nil
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
