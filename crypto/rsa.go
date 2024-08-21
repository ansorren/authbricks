package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/pkg/errors"
)

const (
	CertificatePEMType   = "CERTIFICATE"
	RSAPrivateKeyPEMType = "RSA PRIVATE KEY"
)

// RSAKey is a struct that holds an RSA private/public keypair.
type RSAKey struct {
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
}

// Certificate generates a self-signed certificate for the RSA key.
func (key *RSAKey) Certificate(org string, country string, commonName string, duration time.Duration) ([]byte, []byte, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
			Country:      []string{country},
			CommonName:   commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(duration),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	selfSigned, err := createSelfSignedCertificate(template, key.Private)
	if err != nil {
		return nil, nil, err
	}

	certPEM, keyPEM := encodeCertificateToPEM(selfSigned, key.Private)
	return certPEM, keyPEM, nil
}

// NewRSA4096PEMKey generates an RSA key and returns it in a PEM-encoded format.
func NewRSA4096PEMKey() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to generate 4096 bits RSA key")
	}

	m := x509.MarshalPKCS1PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{
		Type:  RSAPrivateKeyPEMType,
		Bytes: m,
	}), nil
}

func GeneratePEMFromRSAKey(key *rsa.PrivateKey) ([]byte, error) {
	m := x509.MarshalPKCS1PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{
		Type:  RSAPrivateKeyPEMType,
		Bytes: m,
	}), nil
}

// GetRSAKeyFromPEM returns an RSAKey struct from a PEM-encoded private key.
// This is helpful when we have stored the private key in a PEM format.
func GetRSAKeyFromPEM(pemKey []byte) (*RSAKey, error) {
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return nil, fmt.Errorf("found empty PEM block")
	}
	if block.Type != RSAPrivateKeyPEMType {
		return nil, fmt.Errorf("expected block type %s - found type %s", RSAPrivateKeyPEMType, block.Type)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to parse PKCS1 private key")
	}

	return &RSAKey{
		Private: key,
		Public:  &key.PublicKey,
	}, nil
}

// generate4096BitsRSAKey generates a 4096-bits RSA keypair.
func generate4096BitsRSAKey() (*RSAKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to generate 4096 bits RSA key")
	}

	return &RSAKey{
		Private: key,
		Public:  &key.PublicKey,
	}, nil
}

// GenerateRSAPrivateKey generates an RSA private key.
func GenerateRSAPrivateKey() (*rsa.PrivateKey, error) {
	k, err := generate4096BitsRSAKey()
	if err != nil {
		return nil, errors.Wrapf(err, "unable to generate RSA key")
	}
	return k.Private, nil
}
