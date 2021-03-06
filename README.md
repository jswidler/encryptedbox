# encryptedbox

EncryptedBox is an easy to use module for Go that can encrypt or sign any type of data.  It is especially useful when you must serialize your structured data before encrypting or signing it.

There are a number of [examples](./examples/) provided in this repo, which should make it easy to understand how to use this library.

## How it works

EncryptedBox provides a Cipher component which can be configured to encrypt and decrypt data using an easy to understand pipeline which includes serial and deserialization.  Alternatively, it can also sign and verify data.

1. [Serialize structured data to raw binary data](#serialization)
1. [(Optional) Compress the binary data](#compression)
1. [Encrypt or Sign](#encrypt-or-sign)
1. [(Optional) Encode encrypted data or signature as a string](#encode-encrypted-data-or-signature-as-a-string)

The inverse steps must be done in reverse order when decrypting.  Encryptedbox allows you fit these pieces together in a way where the implementation for any of the steps can be easily changed to suit your needs.

### Serialization

Encryption works on binary data, so the first step to encrypt anything is to turn it into a stream of bytes.

encryptedbox can work with easily with Go data structures by serializing them into JSON.  You can also use other provided serializers or create your own to pack your structs into binary more efficiently.

### Compression

Encrypted data appears random, and so compression is no longer possible.  If the data is compressible and you want to compress it, you should do it before encryption.

\* Note in some circumstances, compressing data can cause information to be leaked, especially if an attacker can control part of the message being compressed.  See for instance [CRIME (Compression Ratio Info-leak Made Easy)](https://en.wikipedia.org/wiki/CRIME).

### Encrypt or Sign

EncryptedBox includes components for encrypting with AES for private key encryption and RSA for public key encryption.  It also includes components for HMAC-SHA for symmetric signatures and RSA signing for asymmetric signatures.

The library chooses reasonably safe defaults out of the box:
 * the same plaintext will produce different ciphertext each time it is run
 * you can encrypt as many blocks as you want

### Encode encrypted data or signature as a string

It is common the encrypted payload will need to be encoded into a safe format in order to be transmitted in different contexts, such as a query parameter. At the expense of the message size, encryptedbox has two convenience functions to make this easier, `Cipher.EncryptToString()` and `Cipher.DecryptString()`.  The encoding used by this function can be changed if you are unhappy with the default of `base64.RawURLEncoding`.

## Examples

The most basic example that can be contrived is the following snippet, which encrypts and decrypts `"Hello world!"`

```go
key, _ := aesutil.NewKey256()
cipher, _ := encryptedbox.NewAESCipher(key)

ciphertext, _ := cipher.Encrypt("Hello world!")

var decrypted string
_ = cipher.Decrypt(ciphertext, &decrypted)

fmt.Println(decrypted)
```

There are several more examples located in the [examples](./examples/) directory.

