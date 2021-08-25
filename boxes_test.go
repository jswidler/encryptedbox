package encryptedbox

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/jswidler/encryptedbox/aesutil"
	"github.com/jswidler/encryptedbox/rsautil"
	"github.com/stretchr/testify/assert"
)

var interfaceTests = []interface{}{
	"a string to encode",
	map[string]interface{}{"fieldA": "a message in a struct", "fieldB": "another message in a struct"},
	nil,
	[]interface{}{true, 103.0, "a string", nil},
}

func TestAESHelloWorld(t *testing.T) {
	key, err := aesutil.NewKey256()
	assert.NoError(t, err)
	cipher, _ := NewAESCipher(key)

	testMessage := "Hello world!"
	ciphertext, err := cipher.EncryptToString(testMessage)
	assert.NoError(t, err)

	var decrypted string
	err = cipher.DecryptString(ciphertext, &decrypted)
	assert.NoError(t, err)

	assert.Equal(t, testMessage, decrypted)
	t.Logf("message: %s; encrypted: %s", testMessage, ciphertext)
}

func TestRSAHelloWorld(t *testing.T) {
	key, _, err := rsautil.NewKey2048()
	assert.NoError(t, err)
	cipher, err := NewRSACipher(key)
	assert.NoError(t, err)

	testMessage := "Hello world!"
	ciphertext, err := cipher.EncryptToString(testMessage)
	assert.NoError(t, err)

	var decrypted string
	err = cipher.DecryptString(ciphertext, &decrypted)
	assert.NoError(t, err)

	assert.Equal(t, testMessage, decrypted)
	t.Logf("message: %s; encrypted: %s", testMessage, ciphertext)
}

func TestDefaultAESWithInterface(t *testing.T) {
	key, err := aesutil.NewKey256()
	assert.NoError(t, err)
	cipher, _ := NewAESCipher(key)
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
	privateKey, _, err := rsautil.NewKey2048()
	assert.NoError(t, err)
	cipher, err := NewRSACipher(privateKey)
	assert.NoError(t, err)
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
	key, err := aesutil.NewKey128()
	assert.NoError(t, err)
	message := "a very compressible message "
	for len(message) < 1000 {
		message += message
	}

	// Encrypt without any compression
	encrypter, err := AES(key)
	assert.NoError(t, err)
	cipher := Cipher{
		Encrypter:  encrypter,
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
	privateKey, _, err := rsautil.NewKey2048()
	assert.NoError(t, err)
	encrypter, err := RSA(privateKey)
	assert.NoError(t, err)
	cipher := Cipher{
		Encrypter:  encrypter,
		Serializer: String,
	}

	message := "0123456789ABCDEF"
	for len(message) < 10000 {
		message += message
	}

	var dst string
	ciphertext, err := cipher.Encrypt(message)
	assert.NoError(t, err)
	err = cipher.Decrypt(ciphertext, &dst)
	assert.NoError(t, err)
	assert.Equal(t, message, dst)
}

func TestRSAEncryptWithPublic(t *testing.T) {
	testMessage := "Hello world!"
	privateKey, publicKey, err := rsautil.NewKey2048()
	assert.NoError(t, err)

	encCipher, err := NewRSAEncryptOnlyCipher(publicKey)
	assert.NoError(t, err)

	ciphertext, err := encCipher.EncryptToString(testMessage)
	assert.NoError(t, err)

	decCipher, err := NewRSACipher(privateKey)
	assert.NoError(t, err)

	var decrypted string
	err = decCipher.DecryptString(ciphertext, &decrypted)
	assert.NoError(t, err)

	assert.Equal(t, testMessage, decrypted)
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

	key, err := aesutil.NewKey256()
	assert.NoError(t, err)
	encrypter, err := AES(key)
	assert.NoError(t, err)
	cipher := Cipher{
		Encrypter:  encrypter,
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
	assert.Equal(t, s, dst)
}

func TestBytes(t *testing.T) {
	b := make([]byte, 1024)
	_, err := rand.Read(b)
	assert.NoError(t, err)

	key, err := aesutil.NewKey256()
	assert.NoError(t, err)
	encrypter, err := AES(key)
	assert.NoError(t, err)
	cipher := Cipher{
		Encrypter:  encrypter,
		Serializer: Bytes,
	}
	ciphertext, err := cipher.Encrypt(b)
	assert.NoError(t, err)
	var dst []byte
	err = cipher.Decrypt(ciphertext, &dst)
	assert.NoError(t, err)
	assert.Equal(t, b, dst)
}
