package encryptedbox

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var interfaceTests = []interface{}{
	"a string to encode",
	map[string]interface{}{"fieldA": "a message in a struct", "fieldB": "another message in a struct"},
	nil,
	[]interface{}{true, 103.0, "a string", nil},
}

func TestDefaultAESWithInterface(t *testing.T) {
	key, err := GenerateAESKey()
	assert.NoError(t, err)
	cipher := AESCipher(key)
	for _, test := range interfaceTests {
		// Encrypt to bytes
		out, err := cipher.Encrypt(test)
		assert.NoError(t, err)
		var dst interface{}
		cipher.Decrypt(out, &dst)
		assert.NoError(t, err)
		assert.Equal(t, test, dst)

		// Encrypt to string
		outstr, err := cipher.EncryptToString(test)
		assert.NoError(t, err)
		var dst2 interface{}
		cipher.DecryptString(outstr, &dst2)
		assert.NoError(t, err)
		assert.Equal(t, test, dst2)
	}
}

func TestDefaultRSAWithInterface(t *testing.T) {
	key, err := GenerateRSAKey()
	assert.NoError(t, err)
	cipher := RSACipher(key)
	for _, test := range interfaceTests {
		// Encrypt to bytes
		out, err := cipher.Encrypt(test)
		assert.NoError(t, err)
		var dst interface{}
		cipher.Decrypt(out, &dst)
		assert.NoError(t, err)
		assert.Equal(t, test, dst)

		// Encrypt to string
		outstr, err := cipher.EncryptToString(test)
		assert.NoError(t, err)
		var dst2 interface{}
		cipher.DecryptString(outstr, &dst2)
		assert.NoError(t, err)
		assert.Equal(t, test, dst2)
	}
}

func TestCompression(t *testing.T) {
	key, err := GenerateAESKey()
	assert.NoError(t, err)
	message := "a very compressible message "
	for len(message) < 1000 {
		message += message
	}

	// Encrypt without any compression
	cipher := Cipher{
		Encrypter:  AES(key),
		Serializer: String,
	}
	var out string
	ciphertext, err := cipher.Encrypt(message)
	assert.NoError(t, err)
	err = cipher.Decrypt(ciphertext, &out)
	assert.NoError(t, err)

	assert.GreaterOrEqual(t, len(ciphertext), len(message),
		"ciphertext must be at least as long as the original (via pigeonhole principle)")
	assert.Equal(t, message, out)

	// Turn on compression and check it is shorter
	cipher.Compressor = Zlib
	out = ""
	compressedCiphertext, err := cipher.Encrypt(message)
	assert.NoError(t, err)
	err = cipher.Decrypt(compressedCiphertext, &out)
	assert.NoError(t, err)

	assert.Less(t, len(compressedCiphertext), len(ciphertext))
	assert.Equal(t, message, out)

	// message length: 7168, encrypted length 7184, encrypted with compression: 88
	t.Logf("message length: %d, encrypted length %d, encrypted with compression: %d",
		len(message), len(ciphertext), len(compressedCiphertext))
}

func TestMultiblockRSA(t *testing.T) {
	key, err := GenerateRSAKey()
	assert.NoError(t, err)
	message := "0123456789ABCDEF"
	for len(message) < 10000 {
		message += message
	}
	cipher := Cipher{
		Encrypter:  RSA(key),
		Serializer: String,
	}
	var dst string
	ciphertext, err := cipher.Encrypt(message)
	assert.NoError(t, err)
	err = cipher.Decrypt(ciphertext, &dst)
	assert.NoError(t, err)
	assert.Equal(t, message, dst)
}

func TestJSON(t *testing.T) {
	type TestStruct struct {
		Bool    bool `json:"FOOBAR"`
		Int     int  `json:"123"`
		String1 string
		String2 *string
		String3 *string
		Time    time.Time
	}
	stringRef := func(s string) *string {
		return &s
	}

	key, err := GenerateAESKey()
	assert.NoError(t, err)
	cipher := Cipher{
		Encrypter:  AES(key),
		Compressor: Zlib,
		Serializer: JSON,
	}
	ts, err := time.Parse(time.RFC3339, "2021-08-24T15:39:16.929335-07:00")
	assert.NoError(t, err)
	s := TestStruct{
		Bool:    true,
		Int:     42,
		String1: "a string",
		String2: stringRef("optional string"),
		Time:    ts,
	}
	ciphertext, err := cipher.Encrypt(s)
	assert.NoError(t, err)
	var dst TestStruct

	err = cipher.Decrypt(ciphertext, &dst)
	assert.NoError(t, err)
	assert.Equal(t, s.Time, dst.Time)
}

func TestBytes(t *testing.T) {
	b := make([]byte, 1024)
	_, err := rand.Read(b)
	assert.NoError(t, err)

	key, err := GenerateAESKey()
	assert.NoError(t, err)
	cipher := Cipher{
		Encrypter:  AES(key),
		Serializer: Bytes,
	}
	ciphertext, err := cipher.Encrypt(b)
	assert.NoError(t, err)
	var dst []byte
	err = cipher.Decrypt(ciphertext, &dst)
	assert.NoError(t, err)
	assert.Equal(t, b, dst)
}
