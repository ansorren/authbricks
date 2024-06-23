package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRSA(t *testing.T) {
	_, err := Generate4096BitsRSAKey()
	require.Nil(t, err)
}

func TestNewRSA4096PEMKey(t *testing.T) {
	key, err := NewRSA4096PEMKey()
	require.Nil(t, err)

	_, err = GetRSAKeyFromPEM(key)
	require.Nil(t, err)

	_, err = GetRSAKeyFromPEM([]byte("invalid"))
	require.NotNil(t, err)
}
