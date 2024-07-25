package api

import (
	"crypto"
	"fmt"
	"time"

	abcrypto "go.authbricks.com/bricks/crypto"
	"go.authbricks.com/bricks/ent"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"gopkg.in/go-jose/go-jose.v2/jwt"
)

// issueAccessTokenResponse is the response returned by the issueAccessToken method.
type issueAccessTokenResponse struct {
	ID          string
	AccessToken string
	ExpiresIn   int
	TokenType   string
	Scope       string
}

// issueAccessTokenOptions is a struct to hold the configuration
// when creating an access token.
type issueAccessTokenOptions struct {
	Payload     TokenPayload
	Scopes      string
	Service     *ent.Service
	Application *ent.Application
	PrivateKey  crypto.PrivateKey
	KeyID       string
	Subject     string
	AuthTime    time.Time
}

// issueAccessToken creates a new access token.
func (a *API) issueAccessToken(opts issueAccessTokenOptions) (*issueAccessTokenResponse, error) {
	op := "issueAccessToken"

	now := time.Now()
	// FIXME: This should be configurable
	accessTokenLifetime := DefaultAccessTokenLifetime
	expiry := now.Add(accessTokenLifetime)
	expiresIn := int(expiry.Sub(now).Seconds())
	id := uuid.New().String()
	claims := jwt.Claims{
		Issuer:    opts.Service.Issuer,
		Subject:   opts.Subject,
		Audience:  []string{opts.Payload.ClientID},
		Expiry:    jwt.NewNumericDate(expiry),
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        id,
	}

	cc := accessTokenCustomClaims{
		AuthTime:        jwt.NewNumericDate(opts.AuthTime),
		ClientID:        opts.Payload.ClientID,
		Scope:           opts.Scopes,
		AuthorizedParty: fmt.Sprintf("%s@clients", opts.Payload.ClientID),
	}

	token, err := abcrypto.SignAccessToken(opts.PrivateKey, claims, cc, opts.KeyID)
	if err != nil {
		msg := "unable to sign access token"
		a.Logger.Error(msg, "error", ErrServerError, "error_details", err.Error(), "subject", opts.Subject, "op", op)
		return nil, errors.New(msg)
	}

	return &issueAccessTokenResponse{
		ID:          id,
		AccessToken: token,
		ExpiresIn:   expiresIn,
		TokenType:   TokenTypeBearer,
		Scope:       opts.Scopes,
	}, nil
}
