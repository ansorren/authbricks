package crypto

import (
	"crypto/rand"
	"strings"

	"github.com/pkg/errors"
)

const (
	// Hex is the hexadecimal dictionary.
	Hex = "0123456789abcdefABCDEF"
)

// removePadding removes any number of `=` signs that may have been appended
// to a base64-encoded string.
func removePadding(s string) string {
	if strings.HasSuffix(s, "=") {
		r := strings.TrimRight(s, "=")
		return removePadding(r)
	}
	return s
}

// randomString generates a random password of n characters using the given dictionary.
func randomString(n int, dictionary string) string {
	data := make([]byte, n)
	_, err := rand.Read(data)
	if err != nil {
		panic(errors.New("unable to read data"))
	}
	for k, v := range data {
		data[k] = dictionary[v%byte(len(dictionary))]
	}
	return string(data)
}

// generateHexString generates a cryptographically secure string of n characters.
func generateHexString(n int) string {
	return randomString(n, Hex)
}
