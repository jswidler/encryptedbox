package encryptedbox

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/jswidler/encryptedbox/aesutil"
	"github.com/jswidler/encryptedbox/rsautil"
)

func BenchmarkAESEncrypt128(b *testing.B) {
	aesEncryptBenchmark(b, aesutil.NewKey128)
}

func BenchmarkAESEncrypt192(b *testing.B) {
	aesEncryptBenchmark(b, aesutil.NewKey192)
}

func BenchmarkAESEncrypt256(b *testing.B) {
	aesEncryptBenchmark(b, aesutil.NewKey256)
}

func BenchmarkAESEDecrypt128(b *testing.B) {
	aesDecryptBenchmark(b, aesutil.NewKey128)
}

func BenchmarkAESEDecrypt192(b *testing.B) {
	aesDecryptBenchmark(b, aesutil.NewKey192)
}

func BenchmarkAESEDecrypt256(b *testing.B) {
	aesDecryptBenchmark(b, aesutil.NewKey256)
}

func aesEncryptBenchmark(b *testing.B, keygen func() ([]byte, error)) {
	key, _ := keygen()
	cipher, _ := NewAESCipher(key)
	message := randomString(100)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cipher.Encrypt(message)
		}
	})
}

func aesDecryptBenchmark(b *testing.B, keygen func() ([]byte, error)) {
	key, _ := keygen()
	cipher, _ := NewAESCipher(key)
	ciphertext, _ := cipher.Encrypt(randomString(100))

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			var out string
			cipher.Decrypt(ciphertext, &out)
		}
	})
}

func BenchmarkRSAEncrypt2048(b *testing.B) {
	rsaEncryptBenchmark(b, rsautil.NewKey2048)
}

func BenchmarkRSAEncrypt3072(b *testing.B) {
	rsaEncryptBenchmark(b, rsautil.NewKey3072)
}

func BenchmarkRSAEncrypt4096(b *testing.B) {
	rsaEncryptBenchmark(b, rsautil.NewKey4096)
}

func BenchmarkRSADecrypt2048(b *testing.B) {
	rsaDecryptBenchmark(b, rsautil.NewKey2048)
}

func BenchmarkRSADecrypt3072(b *testing.B) {
	rsaDecryptBenchmark(b, rsautil.NewKey3072)
}

func BenchmarkRSADecrypt4096(b *testing.B) {
	rsaDecryptBenchmark(b, rsautil.NewKey4096)
}

func rsaEncryptBenchmark(b *testing.B, keygen func() ([]byte, []byte, error)) {
	privateKey, _, _ := keygen()
	cipher, _ := NewRSACipher(privateKey)
	ciphertext, _ := cipher.Encrypt(randomString(100))

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			var out string
			cipher.Decrypt(ciphertext, &out)
		}
	})
}

func rsaDecryptBenchmark(b *testing.B, keygen func() ([]byte, []byte, error)) {
	privateKey, _, _ := keygen()
	cipher, _ := NewRSACipher(privateKey)
	ciphertext, _ := cipher.Encrypt(randomString(100))

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			var out string
			cipher.Decrypt(ciphertext, &out)
		}
	})
}

func randomString(len int) string {
	b := make([]byte, len)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return base64.RawStdEncoding.EncodeToString(b)
}
