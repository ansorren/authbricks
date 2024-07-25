package api

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"

	abcrypto "go.authbricks.com/bricks/crypto"
	"go.authbricks.com/bricks/ent"
	"go.authbricks.com/bricks/ent/standardclaims"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"gopkg.in/go-jose/go-jose.v2/jwt"
)

const (
	ScopeOpenID = "openid"
)

// canIssueIDToken returns true if the client is allowed to request an ID token.
func canIssueIDToken(scopes string) bool {
	s := strings.Split(scopes, " ")
	if contains(s, ScopeOpenID) {
		return true
	}
	return false
}

// idTokenOptions is a struct to hold the configuration
// to issue an ID token.
type idTokenOptions struct {
	ID          string
	Application *ent.Application
	ClientID    string
	Service     *ent.Service
	Scopes      string
	CreatedAt   int64
	Nonce       string
	AuthTime    time.Time
	PrivateKey  crypto.PrivateKey
	KeyID       string
	Subject     string
	Code        string
}

// idTokenCustomClaims is a struct to hold the custom claims
// to be included in the ID token.
type idTokenCustomClaims struct {
	Nonce              string           `json:"nonce"`
	AuthTime           *jwt.NumericDate `json:"auth_time"`
	CodeHash           string           `json:"c_hash,omitempty"`
	ent.StandardClaims `json:",inline"`
}

// issueIDToken issues a new ID token.
func (a *API) issueIDToken(ctx context.Context, opts idTokenOptions) (string, error) {
	op := "issueIDToken"
	now := time.Now()
	id := uuid.New().String()
	// FIXME: This should be configurable
	tokenLifetime := DefaultAccessTokenLifetime
	expiry := now.Add(tokenLifetime)
	claims := jwt.Claims{
		Issuer:    opts.Service.Issuer,
		Subject:   opts.Subject,
		Audience:  jwt.Audience{opts.ClientID},
		Expiry:    jwt.NewNumericDate(expiry),
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        id,
	}

	standardClaims, err := a.readStandardClaimsBySubject(ctx, opts.Subject)
	if err != nil {
		msg := "unable to read standard claims"
		a.Logger.Error(msg, "error", ErrServerError, "error_details", err.Error(), "subject", opts.Subject, "op", op)
		return "", errors.New(msg)
	}

	requestedClaims, err := standardClaims.GetRequestedClaims(opts.Scopes)
	if err != nil {
		msg := "unable to retrieve requested claims for subject"
		a.Logger.Error(msg, "error", ErrServerError, "error_details", err.Error(), "subject", opts.Subject, "op", op)
		return "", errors.New(msg)
	}

	cc := getIDTokenCustomClaims(opts, requestedClaims)

	token, err := abcrypto.SignIDToken(opts.PrivateKey, claims, cc, opts.KeyID)
	if err != nil {
		msg := "unable to sign ID token"
		a.Logger.Error(msg, "error", ErrServerError, "error_details", err.Error(), "subject", opts.Subject, "op", op)
		return "", errors.New(msg)
	}
	return token, nil
}

func getIDTokenCustomClaims(opts idTokenOptions, requestedClaims *ent.StandardClaims) idTokenCustomClaims {
	if opts.Code != "" {
		return idTokenCustomClaims{
			Nonce:          opts.Nonce,
			AuthTime:       jwt.NewNumericDate(opts.AuthTime),
			StandardClaims: *requestedClaims,
			CodeHash:       computeCodeHash(opts.Code),
		}
	}
	return idTokenCustomClaims{
		Nonce:          opts.Nonce,
		AuthTime:       jwt.NewNumericDate(opts.AuthTime),
		StandardClaims: *requestedClaims,
	}
}

// computeCodeHash returns the hash of the code.
// Its value is the base64url encoding of the left-most half of the hash
// of the octets of the ASCII representation of the code value, where the hash
// algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE Header.
func computeCodeHash(code string) string {
	// ONLY SHA-256 is supported
	// Calculate the SHA-256 hash of the code value
	hash := sha256.Sum256([]byte(code))

	// Take the left-most 128 bits (16 bytes) of the hash
	leftHalf := hash[:16]

	// base64url encode the left-most 128 bits
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(leftHalf)
}

// readStandardClaimsBySubject retrieves the standard claims for a given subject.
func (a *API) readStandardClaimsBySubject(ctx context.Context, sub string) (*ent.StandardClaims, error) {
	claims, err := a.DB.EntClient.StandardClaims.Query().Where(standardclaims.Subject(sub)).Only(ctx)
	if ent.IsNotFound(err) {
		// if we cannot find the standard claims for the subject, simply return a data structure
		// with the subject set and no other fields.
		return &ent.StandardClaims{
			Subject: sub,
		}, nil
	}
	if err != nil {
		return nil, err
	}
	return claims, nil
}
