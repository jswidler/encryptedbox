package encryptedbox

// The Encrypter type encrypts and decrypts []byte.
//
// Encrypters must know how to find the key they require as the key is not passed in as a function argument.
type Encrypter interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// The Signer type signs and verify []byte.
//
// Signers must know how to find the key they require as the key is not passed in as a function argument.
type Signer interface {
	Sign(data []byte) ([]byte, error)
	Verify(data []byte, signature []byte) error
}

// The Compressor type compresses and decompresses []byte.
type Compressor interface {
	Compress([]byte) ([]byte, error)
	Decompress([]byte) ([]byte, error)
}

// The Serializer type serializes and deserializes the input data types to a []byte.
type Serializer interface {
	Serialize(interface{}) ([]byte, error)
	Deserialize([]byte, interface{}) error
}

// The StringEncoder type encodes and decodes binary data to a string.
type StringEncoder interface {
	EncodeToString(src []byte) string
	DecodeString(s string) ([]byte, error)
}
