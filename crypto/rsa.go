package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/pkg/errors"
)

type RSAKey struct {
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
}

const RSAPrivateKeyPEMType = "RSA PRIVATE KEY"

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

// Generate4096BitsRSAKey generates a 4096-bits RSA keypair.
func Generate4096BitsRSAKey() (*RSAKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to generate 4096 bits RSA key")
	}

	return &RSAKey{
		Private: key,
		Public:  &key.PublicKey,
	}, nil
}
