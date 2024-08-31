package crypto

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCertificate(t *testing.T) {
	key, err := NewRSA4096PEMKey()
	require.Nil(t, err)

	rsaKey, err := GetRSAKeyFromPEM(key)
	require.Nil(t, err)
	require.NotNil(t, rsaKey)

	oneYear := 365 * 24 * time.Hour
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.Nil(t, err)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ACME"},
			Country:      []string{"UK"},
			CommonName:   "authbricks.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(oneYear),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	cert, key, err := rsaKey.Certificate(template)
	require.Nil(t, err)
	require.NotNil(t, cert)
	require.NotNil(t, key)
}
