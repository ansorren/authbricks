package api

import (
	"context"
	"crypto"
	"fmt"
	"time"

	"go.authbricks.com/bricks/ent"

	"github.com/google/uuid"
)

const (
	AccessTokenOnly = iota
	AccessTokenAndIDToken
	AccessTokenAndRefreshToken
	AccessTokenAndIDTokenAndRefreshToken
)

// tokens is the struct that holds all the tokens that were issued.
type tokens struct {
	AccessTokenResponse issueAccessTokenResponse
	IDToken             string
	RefreshToken        string
}

// toSuccessResponse converts the tokens struct to a TokenSuccessResponse, ensuring we only return
// the tokens that were requested.
func (t *tokens) toSuccessResponse() (*TokenSuccessResponse, error) {
	switch t.tokensToReturn() {
	case AccessTokenOnly:
		return &TokenSuccessResponse{
			AccessToken: t.AccessTokenResponse.AccessToken,
			Scope:       t.AccessTokenResponse.Scope,
			ExpiresIn:   t.AccessTokenResponse.ExpiresIn,
			TokenType:   t.AccessTokenResponse.TokenType,
		}, nil
	case AccessTokenAndIDToken:
		return &TokenSuccessResponse{
			AccessToken: t.AccessTokenResponse.AccessToken,
			Scope:       t.AccessTokenResponse.Scope,
			ExpiresIn:   t.AccessTokenResponse.ExpiresIn,
			TokenType:   t.AccessTokenResponse.TokenType,
			IDToken:     t.IDToken,
		}, nil
	case AccessTokenAndRefreshToken:
		return &TokenSuccessResponse{
			AccessToken:  t.AccessTokenResponse.AccessToken,
			Scope:        t.AccessTokenResponse.Scope,
			ExpiresIn:    t.AccessTokenResponse.ExpiresIn,
			TokenType:    t.AccessTokenResponse.TokenType,
			RefreshToken: t.RefreshToken,
		}, nil
	case AccessTokenAndIDTokenAndRefreshToken:
		return &TokenSuccessResponse{
			AccessToken:  t.AccessTokenResponse.AccessToken,
			Scope:        t.AccessTokenResponse.Scope,
			ExpiresIn:    t.AccessTokenResponse.ExpiresIn,
			TokenType:    t.AccessTokenResponse.TokenType,
			IDToken:      t.IDToken,
			RefreshToken: t.RefreshToken,
		}, nil
	default:
		// this should never happen
		return nil, fmt.Errorf("invalid value returned from tokensToReturn: %d", t.tokensToReturn())
	}
}

// tokensToReturn is a helper function to determine which tokens we need to return
func (t *tokens) tokensToReturn() int {
	if t.IDToken != "" && t.RefreshToken != "" {
		return AccessTokenAndIDTokenAndRefreshToken
	}
	if t.IDToken != "" {
		return AccessTokenAndIDToken
	}
	if t.RefreshToken != "" {
		return AccessTokenAndRefreshToken
	}
	return AccessTokenOnly
}

// issueTokens issues all the required tokens.
func (a *API) issueTokens(ctx context.Context, payload TokenPayload, grantedScopes string, application *ent.Application, service *ent.Service, lastPrivateKey crypto.PrivateKey, keyID string, nonce string, subject string, authTime time.Time) (*tokens, error) {
	op := "issueTokens"
	// initialise the two optional tokens to empty strings
	// we will only populate them if we can issue them
	idToken := ""
	refreshToken := ""

	accessTokenOpts := issueAccessTokenOptions{
		Payload:     payload,
		Scopes:      grantedScopes,
		Service:     service,
		Application: application,
		PrivateKey:  lastPrivateKey,
		KeyID:       keyID,
		Subject:     subject,
		AuthTime:    authTime,
	}

	accessTokenResponse, err := a.issueAccessToken(accessTokenOpts)
	if err != nil {
		msg := "server error: cannot issue access token"
		a.Logger.Error(msg, "error", ErrServerError, "error_details", err.Error(), "service", service.Name, "op", op)
		return nil, err
	}

	// if we can issue an ID token, we create it here and return it in the response
	if canIssueIDToken(grantedScopes) {
		opts := idTokenOptions{
			Scopes:      grantedScopes,
			Service:     service,
			Application: application,
			ClientID:    payload.ClientID,
			PrivateKey:  lastPrivateKey,
			KeyID:       keyID,
			Nonce:       nonce,
			AuthTime:    authTime,
			Subject:     subject,
		}
		idToken, err = a.issueIDToken(ctx, opts)
		if err != nil {
			msg := "server error: cannot issue ID token"
			a.Logger.Error(msg, "error", ErrServerError, "error_details", err.Error(), "service", service.Name, "op", op)
			return nil, err
		}
	}

	// If we can issue a refresh token, we create it here and return it in the response
	if canIssueRefreshToken(grantedScopes) {
		opts := refreshTokenOptions{
			ID:            uuid.New().String(),
			Application:   application,
			Service:       service,
			Scopes:        grantedScopes,
			AccessTokenID: accessTokenResponse.ID,
			CreatedAt:     time.Now().Unix(),
			PrivateKey:    lastPrivateKey,
			KeyID:         keyID,
			Subject:       subject,
			AuthTime:      authTime,
		}
		refreshToken, err = a.issueRefreshToken(ctx, opts)
		if err != nil {
			msg := "server error: cannot issue refresh token"
			a.Logger.Error(msg, "error", ErrServerError, "error_details", err.Error(), "service", service.Name, "op", op)
			return nil, err
		}
	}
	return &tokens{
		AccessTokenResponse: *accessTokenResponse,
		IDToken:             idToken,
		RefreshToken:        refreshToken,
	}, nil
}
