package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	_, err := generate4096BitsRSAKey()
	require.Nil(t, err)
}

func TestGenerateRSAPrivateKey(t *testing.T) {
	_, err := GenerateRSAPrivateKey()
	require.Nil(t, err)
}

func TestNewRSA4096PEMKey(t *testing.T) {
	key, err := NewRSA4096PEMKey()
	require.Nil(t, err)

	_, err = GetRSAKeyFromPEM([]byte("invalid"))
	require.NotNil(t, err)

	rsaKey, err := GetRSAKeyFromPEM(key)
	require.Nil(t, err)
	require.NotNil(t, rsaKey)
}
