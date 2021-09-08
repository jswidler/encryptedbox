package encryptedbox

import (
	"strings"
	"testing"
	"time"

	"github.com/jswidler/encryptedbox/aesutil"
	"github.com/jswidler/encryptedbox/rsautil"
	"github.com/stretchr/testify/assert"
)

func TestHMACSHAHelloWorld(t *testing.T) {
	key, err := aesutil.NewKey256()
	assert.NoError(t, err)
	cipher, err := NewHMACSHA256Signer(key)
	assert.NoError(t, err)

	mac, _, err := cipher.Sign("Hello world!")
	assert.NoError(t, err)

	err = cipher.Verify("Hello world!", mac)
	assert.NoError(t, err)

	err = cipher.Verify("Something else", mac)
	assert.Error(t, err)

	t.Logf("mac length (bytes): %d", len(mac))
}

func TestRSASignHelloWorld(t *testing.T) {
	key, _, err := rsautil.NewKey2048()
	assert.NoError(t, err)
	cipher, err := NewRSASigner(key)
	assert.NoError(t, err)

	mac, _, err := cipher.Sign("Hello world!")
	assert.NoError(t, err)

	err = cipher.Verify("Hello world!", mac)
	assert.NoError(t, err)

	err = cipher.Verify("Something else", mac)
	assert.Error(t, err)

	t.Logf("mac length (bytes): %d", len(mac))
}

func TestHMACSHAStruct(t *testing.T) {
	cipher := newCipher(t, aesutil.NewKey256, NewHMACSHA256Signer)

	type TestStruct struct {
		Bool    bool `json:"FOOBAR"`
		Int     int  `json:"123"`
		String1 string
		String2 *string
		String3 *string
		Time    time.Time
	}

	ts, err := time.Parse(time.RFC3339, "2021-08-24T15:39:16.929335-07:00")
	assert.NoError(t, err)
	optionalString := "optional string"
	s := TestStruct{
		Bool:    true,
		Int:     42,
		String1: "a string",
		String2: &optionalString,
		Time:    ts,
	}

	sig, js, err := cipher.Sign(s)
	assert.NoError(t, err)

	dst := TestStruct{}

	// Check we can't restore with invalid signature
	err = cipher.VerifyAndLoad([]byte("{Int: 42}"), sig, &dst)
	assert.Error(t, err)
	assert.NotEqual(t, 42, dst.Int)

	// Check with a valid signature
	err = cipher.VerifyAndLoad(js, sig, &dst)
	assert.NoError(t, err)
	assert.Equal(t, s, dst)
	assert.True(t, strings.Contains(string(js), optionalString), "expected to find test data signed json")
}

func TestBinarySigning(t *testing.T) {
	// I found some challenging cases where the JSON serializer would fail due the interface
	// containing []byte.  The bytes are encoded to a string for json, which changes them.
	// The Gob serializer does not share this problem.
	signer := newCipher(t, aesutil.NewKey256, NewHMACSHA256Signer)
	signer.Serializer = Gob

	// This encrypter is being used to produce []byte which will be sensitive to any mutation.
	encrypter := newCipher(t, aesutil.NewKey256, NewAESCipher)

	msg, err := encrypter.Encrypt("hello world")
	assert.NoError(t, err)

	type Test struct {
		Values map[string]interface{}
		Bytes  []byte
	}
	testMsg := Test{make(map[string]interface{}), msg}
	testMsg.Values["msg"] = msg

	sig, data, err := signer.SignToString(testMsg)
	assert.NoError(t, err)

	var dst Test
	err = signer.VerifyStringAndLoad(data, sig, &dst)
	assert.NoError(t, err)

	sig2, sig2Bytes, err := signer.Sign(testMsg)
	assert.NoError(t, err)
	err = signer.Verify(testMsg, sig2)
	assert.NoError(t, err)
	err = signer.VerifyAndLoad(sig2Bytes, sig2, nil)
	assert.NoError(t, err)
	err = signer.VerifyAndLoad(sig2Bytes, sig2, &dst)
	assert.NoError(t, err)
	assert.Equal(t, testMsg, dst)

	mBytes, ok := dst.Values["msg"].([]byte)
	assert.True(t, ok, "Values[msg] does not have bytes")

	var s string
	err = encrypter.Decrypt(mBytes, &s)
	assert.NoError(t, err)
	assert.Equal(t, "hello world", s)

	err = encrypter.Decrypt(dst.Bytes, &s)
	assert.NoError(t, err)
	assert.Equal(t, "hello world", s)
}
