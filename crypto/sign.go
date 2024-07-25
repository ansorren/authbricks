package crypto

import (
	"crypto"
	"crypto/rsa"
	"fmt"

	"github.com/pkg/errors"
	"gopkg.in/go-jose/go-jose.v2"
	"gopkg.in/go-jose/go-jose.v2/jwt"
)

const (
	// JWTHeaderTypeAccessToken is the header type of the access token,
	// as defined in RFC9068
	// https://www.rfc-editor.org/rfc/rfc9068
	// Also see https://datatracker.ietf.org/doc/html/rfc8725#section-3.11
	// where the use of explicit typing is now recommended.
	JWTHeaderTypeAccessToken = "at+jwt"
	JWTHeaderTypeIDToken     = "id_token+jwt"
)

// signWithRSAKey signs a JWT token with the given RSA key.
func signWithRSAKey(key crypto.PrivateKey, claims jwt.Claims, customClaims interface{}, keyID string, typ string) (string, error) {
	op := "signWithRSAKey"
	headers := map[jose.HeaderKey]interface{}{
		"key_id": keyID,
	}
	signingKey := jose.SigningKey{
		Algorithm: SigningAlgorithmRS256,
		Key:       key,
	}
	opts := &jose.SignerOptions{
		ExtraHeaders: headers,
	}
	opts.WithType(jose.ContentType(typ))

	sig, err := jose.NewSigner(signingKey, opts)
	if err != nil {
		return "", errors.Wrapf(err, "%s: unable to instantiate new signer", op)
	}

	token, err := jwt.Signed(sig).Claims(claims).Claims(customClaims).CompactSerialize()
	if err != nil {
		return "", errors.Wrapf(err, "%s: unable to sign JWT", op)
	}

	return token, nil
}

// signWithKey signs a JWT with the given private key with the given claims.
// Note: only RSA keys are supported.
func signWithKey(k crypto.PrivateKey, claims jwt.Claims, customClaims interface{}, keyID string, typ string) (string, error) {
	op := "signWithKey"
	switch k.(type) {
	case *rsa.PrivateKey:
		token, err := signWithRSAKey(k, claims, customClaims, keyID, typ)
		if err != nil {
			return "", errors.Wrapf(err, "%s: unable to sign with rsa key", op)
		}
		return token, nil
	default:
		return "", fmt.Errorf("%s: unknown key type %T", op, k)
	}
}

// SignAccessToken signs an access token with the given private key.
func SignAccessToken(k crypto.PrivateKey, claims jwt.Claims, customClaims interface{}, keyID string) (string, error) {
	return signWithKey(k, claims, customClaims, keyID, JWTHeaderTypeAccessToken)
}

// SignIDToken signs an ID token with the given private key.
func SignIDToken(k crypto.PrivateKey, claims jwt.Claims, customClaims interface{}, keyID string) (string, error) {
	return signWithKey(k, claims, customClaims, keyID, JWTHeaderTypeIDToken)
}
