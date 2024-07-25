package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"go.authbricks.com/bricks/config"
	"go.authbricks.com/bricks/ent"

	"github.com/labstack/echo/v4"
)

func (a *API) AuthorizationCodeTokenFlow(c echo.Context, payload TokenPayload, service *ent.Service) error {
	op := "AuthorizationCodeTokenFlow"
	// check for empty client ID / authorization code
	if payload.Code == "" {
		msg := "invalid request: authorization code not provided"
		a.Logger.Error(msg, "error", ErrInvalidRequest, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidRequest,
			ErrorDescription: msg,
		})
	}

	if payload.State == "" {
		msg := "invalid request: state not provided"
		a.Logger.Error(msg, "error", ErrInvalidRequest, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidRequest,
			ErrorDescription: msg,
		})
	}

	err := a.compareCredentials(c.Request().Context(), payload.ClientID, payload.ClientSecret)
	if err != nil {
		msg := "invalid request: invalid credentials"
		a.Logger.Error(msg, "error", ErrInvalidRequest, "service", service.Name, "op", op)
		return c.JSON(http.StatusUnauthorized, TokenErrorResponse{
			Error:            ErrInvalidRequest,
			ErrorDescription: msg,
		})
	}
	code, err := a.readAuthorizationCode(c.Request().Context(), payload.Code)
	if ent.IsNotFound(err) {
		msg := "invalid request: invalid code"
		a.Logger.Error(msg, "error", ErrInvalidRequest, "service", service.Name, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidRequest,
			ErrorDescription: msg,
		})
	}
	if err != nil {
		msg := "server error: cannot get authorization code"
		a.Logger.Error(msg, "error", err, "service", service.Name, "op", op)
		return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error:            ErrServerError,
			ErrorDescription: msg,
		})
	}
	// immediately revoke the authorization code
	err = a.revokeAuthorizationCode(c.Request().Context(), code)
	if err != nil {
		msg := "server error: cannot revoke authorization code"
		a.Logger.Error(msg, "error", err, "service", service.Name, "op", op)
		return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error:            ErrServerError,
			ErrorDescription: msg,
		})
	}

	// validate the code
	if codeIsExpired(code, time.Now()) {
		msg := "invalid grant: expired authorization code"
		a.Logger.Error(msg, "error", ErrInvalidGrant, "service", service.Name, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidGrant,
			ErrorDescription: msg,
		})
	}
	if payload.State != code.State {
		msg := "invalid request: invalid state"
		a.Logger.Error(msg, "error", ErrInvalidRequest, "service", service.Name, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidRequest,
			ErrorDescription: msg,
		})
	}

	app, err := a.getApplication(c.Request().Context(), payload.ClientID)
	if ent.IsNotFound(err) {
		// this should not usually happen, as we already checked for the client ID
		// at this point, however we handle it in case the client was deleted
		// in the meantime.
		msg := "invalid client: not found"
		a.Logger.Error(msg, "error", ErrInvalidClient, "service", service.Name, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidClient,
			ErrorDescription: msg,
		})
	}
	if err != nil {
		msg := "server error: cannot get application"
		a.Logger.Error(msg, "error", err, "service", service.Name, "op", op)
		return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error:            ErrServerError,
			ErrorDescription: msg,
		})
	}

	// code is valid, but for another client;
	// let's simply return an invalid grant error
	// without leaking this information
	if app.Name != code.Application {
		msg := "invalid grant: invalid code"
		a.Logger.Error(msg, "error", ErrInvalidGrant, "service", service.Name, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidGrant,
			ErrorDescription: msg,
		})
	}

	// PKCE Code Challenge - RFC 7636
	if err := verifyPKCECodeChallenge(code, payload.CodeVerifier, app); err != nil {
		msg := "invalid request: invalid code verifier"
		a.Logger.Error(msg, "error", ErrInvalidRequest, "error_details", err.Error(), "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidRequest,
			ErrorDescription: err.Error(),
		})
	}

	// check the redirect URI matches the one specified in the authorization code
	if payload.RedirectURI != code.RedirectURI {
		msg := "invalid grant: redirect URI mismatch"
		a.Logger.Error(msg, "error", ErrInvalidGrant, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidGrant,
			ErrorDescription: msg,
		})
	}

	// ensure the application is bound to the service
	gotService, err := app.QueryService().Only(c.Request().Context())
	if ent.IsNotFound(err) {
		msg := "server error: application is not bound to a service"
		a.Logger.Error(msg, "error", ErrServerError, "service", service.Name, "op", op)
		return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error:            ErrServerError,
			ErrorDescription: msg,
		})
	}
	if err != nil {
		msg := "server error: cannot get service"
		a.Logger.Error(msg, "error", err, "service", service.Name, "op", op)
		return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error:            ErrServerError,
			ErrorDescription: msg,
		})
	}

	if gotService.Name != service.Name {
		msg := "invalid request: service does not match"
		a.Logger.Error(msg, "error", ErrInvalidRequest, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidRequest,
			ErrorDescription: msg,
		})
	}

	// this is a sanity check, it should never happen
	// because we should already validate the service name
	// when we insert the authorization code in the database.
	if code.Service != gotService.Name {
		msg := "invalid grant: authorization code not bound to the service"
		a.Logger.Error(msg, "error", ErrInvalidGrant, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidGrant,
			ErrorDescription: msg,
		})
	}

	// ensure the application is allowed to use the authorization code grant type
	// this is a sanity check, as we should ensure the authorization code
	// is only issued to clients that are allowed to use it.
	if !contains(app.GrantTypes, config.GrantTypeAuthorizationCode) {
		msg := "unauthorized client: authorization code grant type not allowed"
		a.Logger.Error(msg, "error", ErrUnauthorizedClient, "service", service.Name, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrUnauthorizedClient,
			ErrorDescription: msg,
		})
	}

	// ensure the code redirect URI is in the list of URIs allowed by the application
	// this is a sanity check, as we should have already validated the redirect URI
	// when we issued the authorization code.
	if !contains(app.RedirectUris, code.RedirectURI) {
		msg := "invalid request: invalid redirect URI"
		a.Logger.Error(msg, "error", ErrInvalidRequest, "service", service.Name, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidRequest,
			ErrorDescription: msg,
		})
	}

	grantedScopes, err := getGrantedScopes(payload.Scope, strings.Split(code.GrantedScopes, " "))
	if err != nil {
		msg := "invalid scope: cannot grant the requested scopes"
		a.Logger.Error(msg, "error", ErrInvalidScope, "error_details", err.Error(), "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidScope,
			ErrorDescription: msg,
		})
	}
	// ensure the application is allowed to use the requested scopes
	// this is a sanity check, as we should check this when we grant
	// the authorization code.
	if err := validateScopes(grantedScopes, service.Scopes); err != nil {
		msg := "invalid scope: cannot grant the requested scopes"
		a.Logger.Error(msg, "error", ErrInvalidScope, "error_details", err.Error(), "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidScope,
			ErrorDescription: msg,
		})
	}

	// issue the token
	lastPrivateKey, keyID, err := a.lastPrivateKeyAndKeyID(c.Request().Context(), service)
	if err != nil {
		msg := "server error: unable to get last private key"
		a.Logger.Error(msg, "error", err, "service", service.Name, "op", op)
		return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error:            ErrServerError,
			ErrorDescription: msg,
		})
	}

	tokens, err := a.issueTokens(c.Request().Context(), payload, grantedScopes, app, service, lastPrivateKey, keyID, code.Nonce, code.Subject, code.AuthTime)
	if err != nil {
		msg := "server error: unable to issue tokens"
		a.Logger.Error(msg, "error", ErrServerError, "op", op, "error_details", err.Error())
		return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error:            ErrServerError,
			ErrorDescription: msg,
		})
	}
	tokenSuccessResponse, err := tokens.toSuccessResponse()
	if err != nil {
		msg := "server error: unable to generate token response"
		a.Logger.Error(msg, "error", ErrServerError, "op", op, "error_details", err.Error())
		return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error:            ErrServerError,
			ErrorDescription: msg,
		})
	}

	c.Response().Header().Set(echo.HeaderCacheControl, "no-store")
	c.Response().Header().Set("Pragma", "no-cache")

	return c.JSON(http.StatusOK, tokenSuccessResponse)
}

// readAuthorizationCode retrieves the authorization code with the given id.
func (a *API) readAuthorizationCode(ctx context.Context, id string) (*ent.AuthorizationCode, error) {
	code, err := a.DB.EntClient.AuthorizationCode.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return code, nil
}

// revokeAuthorizationCode deletes the code from the DB to ensure it cannot be replayed.
func (a *API) revokeAuthorizationCode(ctx context.Context, code *ent.AuthorizationCode) error {
	return a.DB.EntClient.AuthorizationCode.DeleteOneID(code.ID).Exec(ctx)
}
