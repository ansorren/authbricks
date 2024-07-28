package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	abcrypto "go.authbricks.com/bricks/crypto"
	"go.authbricks.com/bricks/ent"

	"github.com/labstack/echo/v4"
)

func (a *API) RefreshTokenFlow(c echo.Context, payload TokenPayload, service *ent.Service) error {
	op := "RefreshTokenFlow"
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
		a.Logger.Error(msg, "error", ErrServerError, "service", service.Name, "error_details", err.Error(), "op", op)
		return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error:            ErrServerError,
			ErrorDescription: msg,
		})
	}

	err = validateRefreshTokenGrant(app, service)
	if err != nil {
		msg := "invalid grant: cannot issue refresh token"
		a.Logger.Error(msg, "error", ErrInvalidGrant, "service", service.Name, "error_details", err.Error(), "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidGrant,
			ErrorDescription: msg,
		})
	}

	grantedScopes, err := getGrantedScopes(payload.Scope, app.Scopes)
	if err != nil {
		msg := "invalid scope: the requested scopes cannot be granted"
		a.Logger.Error(msg, "error", ErrInvalidScope, "service", service.Name, "error_details", err.Error(), "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidScope,
			ErrorDescription: msg,
		})
	}
	err = validateScopes(grantedScopes, service.Scopes)
	if err != nil {
		msg := "invalid scope: the requested scopes cannot be granted"
		a.Logger.Error(msg, "error", ErrInvalidScope, "service", service.Name, "error_details", err.Error(), "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidScope,
			ErrorDescription: msg,
		})
	}

	if !canIssueRefreshToken(grantedScopes) {
		msg := fmt.Sprintf("invalid grant: cannot issue refresh token")
		a.Logger.Error(msg, "error", ErrInvalidGrant, "service", service.Name, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidGrant,
			ErrorDescription: msg,
		})
	}

	// Decrypt the refresh token , attempt to get the last private key
	// In the vast majority of cases the refresh token will be encrypted
	// with the last key of the service keyset. However, if a
	// new key has just been added, the refresh token may be encrypted
	// with an older key. By default, try the last key first, and if
	// that fails, try all the keys in the rotation.
	lastPrivateKey, keyID, err := a.lastPrivateKeyAndKeyID(c.Request().Context(), service)
	if err != nil {
		msg := "server error: cannot get last private key"
		a.Logger.Error(msg, "error", ErrServerError, "service", service.Name, "error_details", err.Error(), "op", op)
		return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error:            ErrServerError,
			ErrorDescription: msg,
		})
	}
	decrypted, err := abcrypto.DecryptWithKey(lastPrivateKey, payload.RefreshToken)
	if err != nil {
		// if we failed to decrypt the token with the last key, try all the keys in the rotation
		a.Logger.Warn("unable to decrypt refresh token with last key, trying all keys", "service", service.Name, "error_details", err.Error(), "op", op)
		ks, err := service.QueryKeySet().Only(c.Request().Context())
		if err != nil {
			msg := "server error: cannot get keyset"
			a.Logger.Error(msg, "error", ErrServerError, "service", service.Name, "error_details", err.Error(), "op", op)
			return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
				Error:            ErrServerError,
				ErrorDescription: msg,
			})
		}
		signingKeys, err := ks.QuerySigningKeys().All(c.Request().Context())
		if err != nil {
			msg := "server error: cannot get signing keys"
			a.Logger.Error(msg, "error", ErrServerError, "service", service.Name, "error_details", err.Error(), "op", op)
			return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
				Error:            ErrServerError,
				ErrorDescription: msg,
			})
		}

		for i, k := range signingKeys {
			privateKey, err := abcrypto.GetRSAKeyFromPEM([]byte(k.Key))
			if err != nil {
				msg := "server error: cannot get RSA key from PEM"
				a.Logger.Error(msg, "error", ErrServerError, "service", service.Name, "error_details", err.Error(), "op", op)
				return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
					Error:            ErrServerError,
					ErrorDescription: msg,
				})
			}
			decrypted, err = abcrypto.DecryptWithKey(privateKey, payload.RefreshToken)
			if err == nil {
				break
			}

			if i == len(signingKeys)-1 {
				msg := "invalid request: cannot decrypt token"
				a.Logger.Error(msg, "error", ErrInvalidRequest, "service", service.Name, "error_details", err.Error(), "op", op)
				return c.JSON(http.StatusBadRequest, TokenErrorResponse{
					Error:            ErrInvalidRequest,
					ErrorDescription: msg,
				})
			}
		}
	}
	u := NewUnmarshaler[*ent.RefreshToken](strings.NewReader(decrypted))
	token, err := u.Unmarshal()
	if err != nil {
		msg := "server error: cannot unmarshal token"
		a.Logger.Error(msg, "error", ErrServerError, "service", service.Name, "error_details", err.Error(), "op", op)
		return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error:            ErrServerError,
			ErrorDescription: msg,
		})
	}

	// we got a decrypted token, now we need to check if it's valid
	oldRefreshToken, err := a.getRefreshToken(c.Request().Context(), token.ID)
	switch {
	case ent.IsNotFound(err):
		// the token is not stored, so it's either been revoked or it's invalid
		// do not leak this information
		msg := "invalid request: invalid refresh token"
		a.Logger.Error(msg, "error", ErrInvalidRequest, "service", service.Name, "error_details", err.Error(), "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidRequest,
			ErrorDescription: msg,
		})
	case ent.IsConstraintError(err):
		msg := "server error: cannot get refresh token"
		a.Logger.Error(msg, "error", ErrServerError, "service", service.Name, "error_details", err.Error(), "op", op)
		return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error:            ErrServerError,
			ErrorDescription: msg,
		})
	default:
	}

	// we got a valid token, we need to check if it is valid for our application
	if oldRefreshToken.Application != app.Name {
		msg := "invalid request: invalid refresh token"
		a.Logger.Error(msg, "error", ErrInvalidRequest, "service", service.Name, "error_details", fmt.Sprintf("token is not valid for application %s", app.Name), "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidRequest,
			ErrorDescription: msg,
		})
	}

	// we got a valid token, validate it is valid for the current service
	if oldRefreshToken.Service != service.Name {
		msg := "invalid request: invalid refresh token"
		a.Logger.Error(msg, "error", ErrInvalidRequest, "service", service.Name, "error_details", fmt.Sprintf("token is not valid for service %s", service.Name), "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidRequest,
			ErrorDescription: msg,
		})
	}

	// we got a valid token, validate it is not expired
	if refreshTokenIsExpired(oldRefreshToken, time.Now()) {
		msg := "invalid request: invalid refresh token"
		a.Logger.Error(msg, "error", ErrInvalidRequest, "service", service.Name, "error_details", "token is expired", "created at", oldRefreshToken.CreatedAt, "lifetime", oldRefreshToken.Lifetime, "op", op)
		return c.JSON(http.StatusBadRequest, TokenErrorResponse{
			Error:            ErrInvalidRequest,
			ErrorDescription: msg,
		})
	}

	//  The `nonce` is not required during the refresh token flow
	// https://bitbucket.org/openid/connect/pull-requests/341/errata-clarified-nonce-during-id-token
	tokens, err := a.issueTokens(c.Request().Context(), payload, grantedScopes, app, service, lastPrivateKey, keyID, "", oldRefreshToken.Subject, oldRefreshToken.AuthTime)
	if err != nil {
		msg := "server error: cannot issue tokens"
		a.Logger.Error(msg, "error", ErrServerError, "op", op, "error_details", err.Error())
		return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error:            ErrServerError,
			ErrorDescription: msg,
		})
	}

	// revoke the old refresh token
	err = a.deleteRefreshToken(c.Request().Context(), oldRefreshToken.ID)
	if err != nil {
		msg := "server error: cannot revoke refresh token"
		a.Logger.Error(msg, "error", ErrServerError, "service", service.Name, "error_details", err.Error(), "op", op)
		return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
			Error:            ErrServerError,
			ErrorDescription: msg,
		})
	}

	tokenSuccessResponse, err := tokens.toSuccessResponse()
	if err != nil {
		msg := "server error: cannot convert tokens to response"
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
