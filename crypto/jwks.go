package crypto

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"gopkg.in/square/go-jose.v2"

	"github.com/pkg/errors"
)

const (
	SigningAlgorithmRS256 = "RS256"
	JWKUseSignature       = "sig"
)

// getKeyID generates the key ID according to the format specified in
// RFC7638 - hash the JWK and base64 URL encode it.
// https://www.rfc-editor.org/rfc/rfc7638#section-3.1
func getKeyID(key *jose.JSONWebKey) (string, error) {
	thumbPrint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", errors.Wrapf(err, "unable to compute key thumbprint")
	}
	// base64 URL encode the string, then remove any padding if present.
	encoded := base64.URLEncoding.EncodeToString(thumbPrint)
	keyID := removePadding(encoded)
	return keyID, nil
}

// newJSONWebKeyFromRSA takes an RSA public key / cert and a DER-encoded certificate and builds a JWK.
func newJSONWebKeyFromRSA(pub *rsa.PublicKey) (*jose.JSONWebKey, error) {
	key := &jose.JSONWebKey{
		Key:       pub,
		Algorithm: SigningAlgorithmRS256,
		Use:       JWKUseSignature,
	}

	// compute key ID
	keyID, err := getKeyID(key)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to generate key id")
	}
	key.KeyID = keyID
	return key, nil
}

// GetKeyID returns the key ID for the given public key.
// Note: Only RSA public keys are supported at the moment.
func GetKeyID(pub crypto.PublicKey) (string, error) {
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("only RSA public keys are supported")
	}
	jwk, err := newJSONWebKeyFromRSA(rsaPub)
	if err != nil {
		return "", err
	}
	return jwk.KeyID, nil
}

// NewKeySet instantiates a new JWK set for the given public keys.
// Note: Only RSA public keys are supported at the moment.
func NewKeySet(pubKeys []crypto.PublicKey) (*jose.JSONWebKeySet, error) {
	ret := make([]jose.JSONWebKey, 0)
	for _, k := range pubKeys {
		p, ok := k.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("unable to convert key to RSA public key")
		}
		key, err := newJSONWebKeyFromRSA(p)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to get new JWK from RSA")
		}
		ret = append(ret, *key)
	}

	return &jose.JSONWebKeySet{
		Keys: ret,
	}, nil
}
