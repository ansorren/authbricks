package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/pkg/errors"
)

// EncryptWithKey encrypts a message with a private key, then base64-URL encodes it.
// Note:
func EncryptWithKey(k crypto.PrivateKey, message []byte) (string, error) {
	op := "EncryptWithKey"
	switch k.(type) {
	case *rsa.PrivateKey:
		privateKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			// this should never happen
			return "", fmt.Errorf("%s: unable to convert RSA private key", op)
		}
		msgLen := len(message)
		pub := privateKey.PublicKey
		hash := sha256.New()
		// split the encrypted message into chunks of size (key size - (2 * hash size) - 2)
		// see https://golang.org/pkg/crypto/rsa/#EncryptOAEP
		step := pub.Size() - 2*hash.Size() - 2
		var cipherText []byte
		for start := 0; start < msgLen; start += step {
			finish := start + step
			if finish > msgLen {
				finish = msgLen
			}

			b, err := rsa.EncryptOAEP(hash, rand.Reader, &pub, message[start:finish], nil)
			if err != nil {
				return "", errors.Wrapf(err, "%s: unable to encrypt message", op)
			}
			cipherText = append(cipherText, b...)
		}
		encoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(cipherText)
		return encoded, nil
	default:
		return "", fmt.Errorf("%s: unknown key type %T", op, k)
	}
}

// DecryptWithKey decrypts a ciphertext with a private key, then base64-URL decodes it.
func DecryptWithKey(k crypto.PrivateKey, cipherText string) (string, error) {
	op := "DecryptWithKey"
	switch k.(type) {
	case *rsa.PrivateKey:
		decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(cipherText)
		if err != nil {
			return "", errors.Wrapf(err, "%s: unable to decode cipher text", op)
		}
		privateKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			// this should never happen
			return "", fmt.Errorf("%s: unable to cast private key", op)
		}
		msgLen := len(decoded)
		step := privateKey.PublicKey.Size()
		var decryptedBytes []byte
		for start := 0; start < msgLen; start += step {
			finish := start + step
			if finish > msgLen {
				finish = msgLen
			}

			hash := sha256.New()
			plainText, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, decoded[start:finish], nil)
			if err != nil {
				return "", errors.Wrapf(err, "%s: unable to decrypt message", op)
			}
			decryptedBytes = append(decryptedBytes, plainText...)
		}
		return string(decryptedBytes), nil
	default:
		return "", fmt.Errorf("%s: unknown key type %T", op, k)
	}
}
