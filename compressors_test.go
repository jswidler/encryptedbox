package encryptedbox

import (
	"testing"

	"github.com/jswidler/encryptedbox/aesutil"
	"github.com/stretchr/testify/assert"
)

func TestGzipCompression(t *testing.T) {
	cipher := newCipher(t, aesutil.NewKey256, NewAESCipher)
	compressorTest(t, cipher, Gzip)
}

func TestZlibCompression(t *testing.T) {
	cipher := newCipher(t, aesutil.NewKey256, NewAESCipher)
	compressorTest(t, cipher, Zlib)
}

func compressorTest(t *testing.T, cipher *Cipher, c Compressor) {
	message := "a very compressible message "
	for len(message) < 1000 {
		message += message
	}

	// Encrypt without any compression
	var out string
	ciphertext, err := cipher.Encrypt(message)
	assert.NoError(t, err)
	err = cipher.Decrypt(ciphertext, &out)
	assert.NoError(t, err)

	assert.GreaterOrEqual(t, len(ciphertext), len(message),
		"ciphertext must be at least as long as the original (via pigeonhole principle)")
	assert.Equal(t, message, out)

	// Turn on compression and check it is shorter
	cipher.Compressor = c
	out = ""
	compressedCiphertext, err := cipher.Encrypt(message)
	assert.NoError(t, err)
	err = cipher.Decrypt(compressedCiphertext, &out)
	assert.NoError(t, err)

	assert.Less(t, len(compressedCiphertext), len(ciphertext))
	assert.Equal(t, message, out)

	t.Logf("message length: %d, encrypted length %d, encrypted with compression: %d",
		len(message), len(ciphertext), len(compressedCiphertext))
}
