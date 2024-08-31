package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// Certificate generates a self-signed certificate for the RSA key.
func (key *RSAKey) Certificate(template *x509.Certificate) ([]byte, []byte, error) {
	selfSigned, err := createSelfSignedCertificate(template, key.Private)
	if err != nil {
		return nil, nil, err
	}

	certPEM, keyPEM := encodeCertificateToPEM(selfSigned, key.Private)
	return certPEM, keyPEM, nil
}

// createSelfSignedCertificate creates a self-signed certificate using the given template and private key.
func createSelfSignedCertificate(template *x509.Certificate, privateKey *rsa.PrivateKey) ([]byte, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return certDER, nil
}

// encodeCertificateToPEM encodes the certificate and private key to PEM format.
func encodeCertificateToPEM(certDER []byte, privateKey *rsa.PrivateKey) ([]byte, []byte) {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  CertificatePEMType,
		Bytes: certDER,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  RSAPrivateKeyPEMType,
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return certPEM, keyPEM
}
