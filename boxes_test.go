package encryptedbox

import (
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

func TestAESInterface(t *testing.T) {
	key, err := GenerateAESKey()
	assert.NoError(t, err)
	cipher := AESCipher(key)
	for _, test := range interfaceTests {
		out, err := cipher.Encrypt(test)
		assert.NoError(t, err)
		var dst interface{}
		cipher.Decrypt(out, &dst)
		assert.NoError(t, err)
		assert.Equal(t, test, dst)
	}
}

func TestRSAInterface(t *testing.T) {
	key, err := GenerateRSAKey()
	assert.NoError(t, err)
	cipher := RSACipher(key)
	for _, test := range interfaceTests {
		out, err := cipher.Encrypt(test)
		assert.NoError(t, err)
		var dst interface{}
		cipher.Decrypt(out, &dst)
		assert.NoError(t, err)
		assert.Equal(t, test, dst)
	}
}

func TestCompression(t *testing.T) {
	key, err := GenerateAESKey()
	assert.NoError(t, err)
	message := "a very compressible message "
	for i := 0; i < 8; i++ {
		message += message
	}
	messageLen := len(message)

	// Encrypt without any compression
	cipher := Cipher{
		Encrypter:  AES(key),
		Serializer: String,
	}
	ciphertext, err := cipher.Encrypt(message)
	assert.NoError(t, err)
	uncompressedLen := len(ciphertext)
	assert.GreaterOrEqual(t, uncompressedLen, messageLen, "ciphertext must be at least as long as the original (via pigeonhole principle)")

	// Check message decrypts
	var out string
	err = cipher.Decrypt(ciphertext, &out)
	assert.NoError(t, err)
	assert.Equal(t, message, out)

	// Turn on compression and check it is shorter
	cipher.Compressor = Zlib
	ciphertext, err = cipher.Encrypt(message)
	assert.NoError(t, err)
	compressedLen := len(ciphertext)
	assert.Less(t, compressedLen, uncompressedLen)

	// Check message decrypts
	out = ""
	err = cipher.Decrypt(ciphertext, &out)
	assert.NoError(t, err)
	assert.Equal(t, message, out)

	// message length: 7168, encrypted length 7184, encrypted with compression: 88
	t.Logf("message length: %d, encrypted length %d, encrypted with compression: %d", messageLen, uncompressedLen, compressedLen)
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
