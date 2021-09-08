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

	// Signer controls the signing and verification steps.
	Signer Signer

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

func NewHMACSHA256Signer(aesKey []byte) (*Cipher, error) {
	signer, err := HMACSHA256(aesKey)
	if err != nil {
		return nil, err
	}
	return &Cipher{
		Serializer:    JSON,
		Signer:        signer,
		StringEncoder: DefaultStringEncoder,
	}, nil
}

func NewRSASigner(privateKeyPem []byte) (*Cipher, error) {
	signer, err := RSASigner(privateKeyPem)
	if err != nil {
		return nil, err
	}
	return &Cipher{
		Serializer:    JSON,
		Signer:        signer,
		StringEncoder: DefaultStringEncoder,
	}, nil
}

func NewRSASignerVerifyOnly(publicKeypem []byte) (*Cipher, error) {
	signer, err := RSAVerifyOnly(publicKeypem)
	if err != nil {
		return nil, err
	}
	return &Cipher{
		Serializer:    JSON,
		Signer:        signer,
		StringEncoder: DefaultStringEncoder,
	}, nil
}

func (c Cipher) Encrypt(data interface{}) ([]byte, error) {
	b, err := serialize(data, c.Serializer, c.Compressor)
	if err != nil {
		return nil, err
	}
	return c.Encrypter.Encrypt(b)
}

func (c Cipher) Decrypt(ciphertext []byte, dst interface{}) error {
	data, err := c.Encrypter.Decrypt(ciphertext)
	if err != nil {
		return err
	}
	return deserialize(data, dst, c.Serializer, c.Compressor)
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

func (c Cipher) Sign(data interface{}) (signature string, bytesSigned []byte, err error) {
	bytesSigned, err = serialize(data, c.Serializer, c.Compressor)
	if err != nil {
		return "", nil, err
	}
	sig, err := c.Signer.Sign(bytesSigned)
	if err != nil {
		return "", nil, err
	}
	return c.StringEncoder.EncodeToString(sig), bytesSigned, err
}

func (c Cipher) Verify(data interface{}, signature string) error {
	sig, err := c.StringEncoder.DecodeString(signature)
	if err != nil {
		return err
	}
	b, err := serialize(data, c.Serializer, c.Compressor)
	if err != nil {
		return err
	}
	return c.Signer.Verify(b, sig)
}

func (c Cipher) VerifyAndLoad(signedData []byte, signature string, dst interface{}) error {
	sig, err := c.StringEncoder.DecodeString(signature)
	if err != nil {
		return err
	}
	err = c.Signer.Verify(signedData, sig)
	if err != nil {
		return err
	}
	if dst == nil {
		return nil
	}
	return deserialize(signedData, dst, c.Serializer, c.Compressor)
}

func (c Cipher) SignToString(data interface{}) (signature string, signedData string, err error) {
	signature, bytesSigned, err := c.Sign(data)
	if err != nil {
		return "", "", err
	}
	return signature, c.StringEncoder.EncodeToString(bytesSigned), nil
}

func (c Cipher) VerifyStringAndLoad(signedData string, signature string, dst interface{}) error {
	bytesSigned, err := c.StringEncoder.DecodeString(signedData)
	if err != nil {
		return err
	}
	return c.VerifyAndLoad(bytesSigned, signature, dst)
}

func serialize(data interface{}, s Serializer, c Compressor) ([]byte, error) {
	b, err := s.Serialize(data)
	if err != nil {
		return nil, err
	}
	if c != nil {
		return c.Compress(b)
	}
	return b, nil
}

func deserialize(data []byte, dst interface{}, s Serializer, c Compressor) error {
	b := data
	if c != nil {
		var err error
		b, err = c.Decompress(data)
		if err != nil {
			return err
		}
	}
	return s.Deserialize(b, dst)
}
