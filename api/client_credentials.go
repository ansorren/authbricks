package api

import (
	"context"
	"crypto"
	"fmt"
	"net/http"
	"time"

	abcrypto "go.authbricks.com/bricks/crypto"
	"go.authbricks.com/bricks/ent"
	"go.authbricks.com/bricks/ent/credentials"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gopkg.in/go-jose/go-jose.v2/jwt"
)

const (
	// DefaultAccessTokenLifetime is the default lifetime of an access token.
	DefaultAccessTokenLifetime = 24 * time.Hour
)

func (a *API) ClientCredentialsTokenFlow(c echo.Context, payload TokenPayload, service *ent.Service) error {
	op := "ClientCredentialsTokenFlow"
	a.Logger.Info("starting client credentials token flow", "service", service.Name, "op", op)
	if payload.Audience == "" {
		msg := "invalid request: audience not provided"
		a.Logger.Error(msg, "error", ErrInvalidRequest, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidRequest,
			ErrorDescription: msg,
		})
	}
	if payload.Audience != service.Issuer {
		msg := "invalid request: invalid audience"
		a.Logger.Error(msg, "error", ErrInvalidRequest, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidRequest,
			ErrorDescription: msg,
		})
	}
	// compare the client credentials
	err := a.compareCredentials(c.Request().Context(), payload.ClientID, payload.ClientSecret)
	if ent.IsNotFound(err) {
		msg := "client not found"
		a.Logger.Error(msg, "error", ErrInvalidClient, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidClient,
			ErrorDescription: msg,
		})
	}
	if ent.IsConstraintError(err) {
		msg := "server error"
		a.Logger.Error(msg, "error", ErrServerError, "service", service.Name, "op", op)
		return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error:            ErrServerError,
			ErrorDescription: msg,
		})
	}
	if err != nil {
		msg := "invalid client secret"
		a.Logger.Error(msg, "error", ErrInvalidClient, "service", service.Name, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidClient,
			ErrorDescription: msg,
		})
	}

	app, err := a.getApplication(c.Request().Context(), payload.ClientID)
	// this should not happen usually, as we have already queried the application by clientID
	// at this point, however if there's a race condition where the application is deleted
	// after the check we should return an error.
	if ent.IsNotFound(err) {
		msg := "application not found"
		a.Logger.Error(msg, "error", ErrInvalidClient, "service", service.Name, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidClient,
			ErrorDescription: msg,
		})
	}
	if ent.IsConstraintError(err) {
		msg := "server error while getting application"
		a.Logger.Error(msg, "error", ErrServerError, "service", service.Name, "op", op)
		return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error:            ErrServerError,
			ErrorDescription: msg,
		})
	}
	if err != nil {
		msg := "unable to get application"
		a.Logger.Error(msg, "error", err, "service", service.Name, "op", op)
		return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error:            ErrServerError,
			ErrorDescription: msg,
		})
	}
	// check if the application is allowed to request a token against the given service
	err = a.isAllowedToRequestToken(c.Request().Context(), app, service)
	if ent.IsConstraintError(err) {
		msg := "server error while checking if the application is allowed to request a token"
		a.Logger.Error(msg, "error", ErrServerError, "service", service.Name, "op", op)
		return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error:            ErrServerError,
			ErrorDescription: msg,
		})
	}
	if err != nil {
		msg := "unauthorized client"
		a.Logger.Error(msg, "error", ErrInvalidClient, "error_details", err.Error(), "service", service.Name, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrUnauthorizedClient,
			ErrorDescription: msg,
		})
	}

	grantedScopes, err := getGrantedScopes(payload.Scope, app.Scopes)
	if err != nil {
		msg := "invalid scope: cannot grant the scopes requested"
		a.Logger.Error(msg, "error", ErrInvalidScope, "error_details", err.Error(), "service", service.Name, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidScope,
			ErrorDescription: msg,
		})
	}

	if err := validateScopes(grantedScopes, service.Scopes); err != nil {
		msg := "invalid scope: cannot grant the scopes requested"
		a.Logger.Error(msg, "error", ErrInvalidScope, "error_details", err.Error(), "service", service.Name, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidScope,
			ErrorDescription: msg,
		})
	}

	// generate the token
	privKey, keyID, err := a.lastPrivateKeyAndKeyID(c.Request().Context(), service)
	if err != nil {
		msg := "server error while getting signing key"
		a.Logger.Error(msg, "error", err, "service", service.Name, "op", op)
		return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error:            ErrServerError,
			ErrorDescription: msg,
		})
	}

	jwtID := uuid.New().String()
	now := time.Now()
	// FIXME: this should be configurable
	expiry := now.Add(DefaultAccessTokenLifetime)
	expiresIn := int(expiry.Sub(now).Seconds())
	claims := jwt.Claims{
		Issuer:    service.Issuer,
		Subject:   jwtID,
		Audience:  []string{service.Issuer},
		Expiry:    jwt.NewNumericDate(expiry),
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        jwtID,
	}
	cc := accessTokenCustomClaims{
		AuthTime:        jwt.NewNumericDate(now),
		ClientID:        payload.ClientID,
		Scope:           grantedScopes,
		AuthorizedParty: fmt.Sprintf("%s@clients", payload.ClientID),
	}
	token, err := abcrypto.SignAccessToken(privKey, claims, cc, keyID)
	if err != nil {
		msg := "server error: cannot sign token"
		a.Logger.Error(msg, "error", ErrServerError, "error_details", err.Error(), "service", service.Name, "op", op)
		return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error:            ErrServerError,
			ErrorDescription: msg,
		})
	}

	c.Response().Header().Set(echo.HeaderCacheControl, "no-store")
	c.Response().Header().Set("Pragma", "no-cache")
	return c.JSON(http.StatusOK, TokenSuccessResponse{
		AccessToken: token,
		Scope:       grantedScopes,
		ExpiresIn:   expiresIn,
		TokenType:   TokenTypeBearer,
	})
}

// lastPrivateKeyAndKeyID returns the last private key and its key ID associated with the given service.
func (a *API) lastPrivateKeyAndKeyID(ctx context.Context, service *ent.Service) (crypto.PrivateKey, string, error) {
	ks, err := service.QueryKeySet().Only(ctx)
	if err != nil {
		return nil, "", err
	}
	signingKeys, err := ks.QuerySigningKeys().All(ctx)
	if err != nil {
		return nil, "", err
	}
	if len(signingKeys) == 0 {
		return nil, "", fmt.Errorf("no signing keys found")
	}

	lastKey := signingKeys[len(signingKeys)-1]
	rsaKey, err := abcrypto.GetRSAKeyFromPEM([]byte(lastKey.Key))
	if err != nil {
		return nil, "", err
	}

	keyID, err := abcrypto.GetKeyID(rsaKey.Public)
	if err != nil {
		return nil, "", err
	}
	return rsaKey.Private, keyID, nil
}

func (a *API) isAllowedToRequestToken(ctx context.Context, app *ent.Application, service *ent.Service) error {
	// check if the application is allowed to request a token against the given service
	s, err := app.QueryService().Only(ctx)
	if err != nil {
		return err
	}

	if s.Issuer != service.Issuer {
		return fmt.Errorf("service issuer mismatch: expected %s - got %s", service.Issuer, s.Issuer)
	}
	return nil
}

// compareCredentials compares the clientID and clientSecret with the stored credentials.
func (a *API) compareCredentials(ctx context.Context, clientID string, clientSecret string) error {
	creds, err := a.DB.EntClient.Credentials.Query().Where(credentials.ClientID(clientID)).Only(ctx)
	if err != nil {
		return err
	}
	if creds.ClientSecret != clientSecret {
		return fmt.Errorf("invalid client secret")
	}
	return nil
}
