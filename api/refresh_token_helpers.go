package api

import (
	"context"
	"crypto"
	"encoding/json"
	"strings"
	"time"

	abcrypto "go.authbricks.com/bricks/crypto"
	"go.authbricks.com/bricks/ent"

	"github.com/pkg/errors"
)

const (
	RefreshTokenLifetime = 24 * time.Hour
	ScopeOfflineAccess   = "offline_access"
)

// canIssueRefreshToken returns true if the client is allowed to request a refresh token.
func canIssueRefreshToken(scopes string) bool {
	s := strings.Split(scopes, " ")
	if contains(s, ScopeOfflineAccess) {
		return true
	}
	return false
}

// refreshTokenOptions holds the configuration required
// to issue a refresh token.
type refreshTokenOptions struct {
	ID            string
	Application   *ent.Application
	Service       *ent.Service
	Scopes        string
	AccessTokenID string
	CreatedAt     int64
	PrivateKey    crypto.PrivateKey
	KeyID         string
	Subject       string
	AuthTime      time.Time
}

// issueRefreshToken issues a refresh token. The refresh token is encrypted with the server private key
// and returned to the RP, but it is not a JWT to prevent misconfigurations where the refresh token
// is sent to a resource server and the resource server simply allows the request
// because it's signed by the same key.
func (a *API) issueRefreshToken(ctx context.Context, opts refreshTokenOptions) (string, error) {
	op := "issueRefreshToken"
	lifetime := RefreshTokenLifetime
	token := &ent.RefreshToken{
		ID:            opts.ID,
		Application:   opts.Application.Name,
		Service:       opts.Service.Name,
		Scopes:        opts.Scopes,
		CreatedAt:     opts.CreatedAt,
		Lifetime:      int64(lifetime.Seconds()),
		AccessTokenID: opts.AccessTokenID,
		KeyID:         opts.KeyID,
		Subject:       opts.Subject,
		AuthTime:      opts.AuthTime,
	}
	b, err := json.Marshal(token)
	if err != nil {
		msg := "unable to marshal refresh token"
		a.Logger.Error(msg, "error", ErrServerError, "error_details", err.Error(), "subject", opts.Subject, "op", op)
		return "", errors.New(msg)
	}

	encrypted, err := abcrypto.EncryptWithKey(opts.PrivateKey, b)
	if err != nil {
		msg := "unable to encrypt refresh token"
		a.Logger.Error(msg, "error", ErrServerError, "error_details", err.Error(), "subject", opts.Subject, "op", op)
		return "", errors.New(msg)
	}

	// store the refresh token
	err = a.storeRefreshToken(ctx, token)
	if err != nil {
		msg := "unable to store refresh token"
		a.Logger.Error(msg, "error", ErrServerError, "error_details", err.Error(), "subject", opts.Subject, "op", op)
		return "", errors.New(msg)
	}
	return encrypted, nil
}

// storeFreshToken stores a refresh token in the raft backend.
func (a *API) storeRefreshToken(ctx context.Context, token *ent.RefreshToken) error {
	op := "storeRefreshToken"
	_, err := a.DB.EntClient.RefreshToken.Create().
		SetID(token.ID).
		SetApplication(token.Application).
		SetService(token.Service).
		SetScopes(token.Scopes).
		SetCreatedAt(token.CreatedAt).
		SetAccessTokenID(token.AccessTokenID).
		SetLifetime(token.Lifetime).
		SetSubject(token.Subject).
		SetKeyID(token.KeyID).
		SetAuthTime(token.AuthTime).
		Save(ctx)
	if err != nil {
		return errors.Wrapf(err, "%s: unable to store refresh token", op)
	}
	return nil
}

// getRefreshToken retrieves the refresh token with the given ID.
func (a *API) getRefreshToken(ctx context.Context, id string) (*ent.RefreshToken, error) {
	token, err := a.DB.EntClient.RefreshToken.Get(ctx, id)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get refresh token")
	}
	return token, nil
}

// deleteRefreshToken deletes the refresh token with the given ID.
func (a *API) deleteRefreshToken(ctx context.Context, id string) error {
	return a.DB.EntClient.RefreshToken.DeleteOneID(id).Exec(ctx)
}
