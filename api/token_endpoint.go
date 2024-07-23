package api

import (
	"context"
	"fmt"
	"net/http"

	"go.authbricks.com/bricks/config"
	"go.authbricks.com/bricks/ent"
	"go.authbricks.com/bricks/ent/credentials"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeRefreshToken      = "refresh_token"

	TokenTypeBearer = "Bearer"
)

// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
// documents the below error codes for the client credentials flow.
// Note that the `server_error` is absent from the spec
// but has been added in the errata
// https://www.rfc-editor.org/errata/eid4745
const (
	ErrInvalidClient           = "invalid_client"
	ErrInvalidGrant            = "invalid_grant"
	ErrInvalidRequest          = "invalid_request"
	ErrInvalidScope            = "invalid_scope"
	ErrServerError             = "server_error"
	ErrUnauthorizedClient      = "unauthorized_client"
	ErrUnsupportedGrantType    = "unsupported_grant_type"
	ErrUnsupportedResponseType = "unsupported_response_type"
)

// TokenSuccessResponse is the response given by the API server when successful.
type TokenSuccessResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

// TokenErrorResponse is the response given by the API server when an error occurs.
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// TokenPayload is the payload passed to the token endpoint.
type TokenPayload struct {
	Scope        string `json:"scope,omitempty"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	Audience     string `json:"audience"`
	GrantType    string `json:"grant_type"`
	RedirectURI  string `json:"redirect_uri"`
	Code         string `json:"code"`
	State        string `json:"state"`
	CodeVerifier string `json:"code_verifier,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// accessTokenCustomClaims is a struct to hold the token custom claims.
type accessTokenCustomClaims struct {
	// ClientID is required by RFC9068
	// https://datatracker.ietf.org/doc/html/rfc9068#name-data-structure
	ClientID        string           `json:"client_id,omitempty"`
	Scope           string           `json:"scope,omitempty"`
	AuthorizedParty string           `json:"azp,omitempty"`
	AuthTime        *jwt.NumericDate `json:"auth_time,omitempty"`
}

const (
	// invalidAuthenticationMethod is used when there is an invalid authentication method
	invalidAuthenticationMethod = "invalid_authentication_method"
)

// getTokenPayload populates the TokenPayload choosing from a variety of different
// authentication mechanisms. The second value returned is the actual authentication
// method used.
func getTokenPayload(c echo.Context) (TokenPayload, string, error) {
	// Check the value of the `Content-Type` header
	header := c.Request().Header.Get(echo.HeaderContentType)
	// default to `client_secret_basic` authentication method
	// when the HTTP Basic Authentication header is detected
	clientID, clientSecret, ok := c.Request().BasicAuth()
	if header == echo.MIMEApplicationForm && ok {
		return clientSecretBasic(c, clientID, clientSecret)
	}

	// Fallback to the `client_secret_post` authentication method
	// when we don't detect the Basic Auth but the `Content-Type`
	// complies with the spec
	if header == echo.MIMEApplicationForm {
		return clientSecretPOST(c)
	}

	return TokenPayload{}, invalidAuthenticationMethod, fmt.Errorf("invalid content type header - only %s is supported", echo.MIMEApplicationForm)
}

func clientSecretPOST(c echo.Context) (TokenPayload, string, error) {
	payload := TokenPayload{}
	err := echo.FormFieldBinder(c).
		String("scope", &payload.Scope).
		String("client_id", &payload.ClientID).
		String("client_secret", &payload.ClientSecret).
		String("audience", &payload.Audience).
		String("grant_type", &payload.GrantType).
		String("redirect_uri", &payload.RedirectURI).
		String("code", &payload.Code).
		String("state", &payload.State).
		String("code_verifier", &payload.CodeVerifier).
		String("refresh_token", &payload.RefreshToken).
		BindError()
	if err != nil {
		return TokenPayload{}, config.AuthenticationMethodClientSecretPost, errors.Wrapf(err, "unable to parse form fields")
	}
	return payload, config.AuthenticationMethodClientSecretPost, nil
}

func clientSecretBasic(c echo.Context, clientID string, clientSecret string) (TokenPayload, string, error) {
	payload := TokenPayload{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
	err := echo.FormFieldBinder(c).
		String("scope", &payload.Scope).
		String("audience", &payload.Audience).
		String("grant_type", &payload.GrantType).
		String("redirect_uri", &payload.RedirectURI).
		String("code", &payload.Code).
		String("state", &payload.State).
		String("code_verifier", &payload.CodeVerifier).
		String("refresh_token", &payload.RefreshToken).
		BindError()
	if err != nil {
		return TokenPayload{}, config.AuthenticationMethodClientSecretBasic, errors.Wrapf(err, "unable to parse form fields")
	}
	return payload, config.AuthenticationMethodClientSecretBasic, nil
}

func (a *API) TokenHandler(service *ent.Service) func(echo.Context) error {
	return func(c echo.Context) error {
		op := "TokenHandler"
		serviceAuthMethods, err := a.serviceAuthMethods(c.Request().Context(), service)
		if err != nil {
			msg := "unable to get allowed authentication methods"
			a.Logger.Error(msg, "error", err, "service", service.Name, "op", op)
			return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
				Error:            ErrServerError,
				ErrorDescription: msg,
			})
		}

		payload, authMethod, err := getTokenPayload(c)
		if err != nil {
			msg := "invalid request: unable to unmarshal payload"
			a.Logger.Error(msg, "error", ErrInvalidRequest, "service", service.Name, "op", op)
			return c.JSON(http.StatusBadRequest, TokenErrorResponse{
				Error:            ErrInvalidRequest,
				ErrorDescription: msg,
			})
		}

		allowedAuthMethods, err := a.allowedAuthMethods(c.Request().Context(), serviceAuthMethods, payload.ClientID)
		if ent.IsNotFound(err) {
			msg := "client not found"
			a.Logger.Error(msg, "error", ErrInvalidClient, "service", service.Name, "op", op)
			return c.JSON(http.StatusBadRequest, TokenErrorResponse{
				Error:            ErrInvalidClient,
				ErrorDescription: msg,
			})
		}
		if err != nil {
			msg := "unable to get allowed authentication methods"
			a.Logger.Error(msg, "error", err, "service", service.Name, "op", op)
			return c.JSON(http.StatusInternalServerError, TokenErrorResponse{
				Error:            ErrServerError,
				ErrorDescription: msg,
			})
		}
		// Check if the authentication method is allowed
		if !contains(allowedAuthMethods, authMethod) {
			msg := fmt.Sprintf("invalid authentication method - %s", authMethod)
			a.Logger.Error(msg, "error", invalidAuthenticationMethod, "service", service.Name, "op", op)
			return c.JSON(http.StatusBadRequest, TokenErrorResponse{
				Error:            ErrInvalidRequest,
				ErrorDescription: msg,
			})
		}

		switch payload.GrantType {
		case GrantTypeAuthorizationCode:
			return a.AuthorizationCodeTokenFlow(c, payload, service)
		case GrantTypeClientCredentials:
			return a.ClientCredentialsTokenFlow(c, payload, service)
		case GrantTypeRefreshToken:
			return a.RefreshTokenFlow(c, payload, service)
		default:
			msg := fmt.Sprintf("unsupported grant type: %s", payload.GrantType)
			a.Logger.Error(msg, "error", ErrUnsupportedGrantType, "service", service.Name, "op", op)
			return c.JSON(http.StatusBadRequest, TokenErrorResponse{
				Error:            ErrUnsupportedGrantType,
				ErrorDescription: msg,
			})
		}
	}
}

// getApplication retrieves the application with the given client ID.
func (a *API) getApplication(ctx context.Context, clientID string) (*ent.Application, error) {
	app, err := a.DB.EntClient.Credentials.Query().Where(credentials.ClientID(clientID)).QueryApplication().Only(ctx)
	if err != nil {
		return nil, err
	}
	return app, nil
}

// allowedAuthMethods returns the allowed authentication methods for the given client ID, merging the results with
// the authentication methods allowed on the server side.
func (a *API) allowedAuthMethods(ctx context.Context, serviceAuthMethods []string, clientID string) ([]string, error) {
	app, err := a.getApplication(ctx, clientID)
	if err != nil {
		return nil, err
	}
	return mergeAuthenticationMethods(serviceAuthMethods, app.AllowedAuthenticationMethods), nil
}

// mergeAuthenticationMethods merges the server authentication methods with the application authentication methods,
// returning the intersection of the two.
func mergeAuthenticationMethods(serverAuthMethods []string, appAuthMethods []string) []string {
	var ret []string
	for _, appAuthMethod := range appAuthMethods {
		if contains(serverAuthMethods, appAuthMethod) {
			ret = append(ret, appAuthMethod)
		}
	}
	return ret
}
