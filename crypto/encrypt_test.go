package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryptWithKey(t *testing.T) {
	rsaKey, err := generate4096BitsRSAKey()
	require.Nil(t, err)

	message := "Hello world"
	cipher, err := EncryptWithKey(rsaKey.Private, []byte(message))
	require.Nil(t, err)
	require.NotEmpty(t, cipher)

	plain, err := DecryptWithKey(rsaKey.Private, cipher)
	require.Nil(t, err)

	require.Equal(t, message, plain)
}
