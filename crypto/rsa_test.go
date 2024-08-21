package crypto

import (
	"testing"
	"time"

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

func TestCertificate(t *testing.T) {
	key, err := NewRSA4096PEMKey()
	require.Nil(t, err)

	rsaKey, err := GetRSAKeyFromPEM(key)
	require.Nil(t, err)
	require.NotNil(t, rsaKey)

	oneYear := 365 * 24 * time.Hour
	cert, key, err := rsaKey.Certificate("ACME", "UK", "authbricks.com", oneYear)
	require.Nil(t, err)
	require.NotNil(t, cert)
	require.NotNil(t, key)
}
