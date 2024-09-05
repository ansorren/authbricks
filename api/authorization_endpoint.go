package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.authbricks.com/bricks/ent"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

const (
	ResponseModeFragment          = "fragment"
	ResponseModeQuery             = "query"
	ResponseTypeAuthorizationCode = "code"
	ResponseTypeIDToken           = "id_token"
	ResponseTypeCodeIDToken       = "code id_token"
	SessionAuthenticate           = "authenticate"
)

// allowedCodeChallengeMethods is the list of allowed code challenge methods.
var allowedCodeChallengeMethods = []string{PKCECodeChallengeMethodPlain, PKCECodeChallengeMethodS256}

// authorizationPayloadFromQueryParams returns an AuthorizationPayload from the query parameters.
func authorizationPayloadFromQueryParams(c echo.Context, serviceName string) *ent.AuthorizationPayload {
	q := c.QueryParams()
	return &ent.AuthorizationPayload{
		ID:                  uuid.New().String(),
		ResponseType:        q.Get("response_type"),
		ResponseMode:        q.Get("response_mode"),
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Nonce:               q.Get("nonce"),
		ServiceName:         serviceName,
	}
}

func (a *API) AuthorizationHandler(service *ent.Service) func(echo.Context) error {
	return func(c echo.Context) error {
		payload := authorizationPayloadFromQueryParams(c, service.Name)
		return a.authorizationFlow(c, service, payload)
	}
}

// mergeResponseTypes merges the response types of the service and the application.
func mergeResponseTypes(serviceResponseTypes, appResponseTypes []string) []string {
	var ret []string
	for _, s := range appResponseTypes {
		if contains(serviceResponseTypes, s) {
			ret = append(ret, s)
		}
	}
	return ret
}

// validatePayload checks that the given payload is valid. The first value
// is an error title used to inform the user of the error.
func (a *API) validatePayload(payload *ent.AuthorizationPayload, service *ent.Service, app *ent.Application) (string, error) {
	allowedResponseTypes := mergeResponseTypes(service.ResponseTypes, app.ResponseTypes)
	if !contains(allowedResponseTypes, payload.ResponseType) {
		msg := fmt.Sprintf("invalid request: unsupported response type %s", payload.ResponseType)
		a.Logger.Error(msg, "error", ErrUnsupportedResponseType)
		return ErrUnsupportedResponseType, fmt.Errorf(msg)
	}

	// in addition to the response modes defined in the OIDC spec, we also support
	// the empty response mode (aka not passing the value at all),
	// which means that the response mode will be the default
	// one for the given response type.
	if !contains([]string{ResponseModeQuery, ResponseModeFragment, ""}, payload.ResponseMode) {
		msg := fmt.Sprintf("invalid request: unsupported response mode %s", payload.ResponseMode)
		a.Logger.Error(msg, "error", ErrInvalidRequest)
		return ErrInvalidRequest, fmt.Errorf(msg)
	}

	if payload.State == "" {
		msg := fmt.Sprintf("invalid request: missing state")
		a.Logger.Error(msg, "error", ErrInvalidRequest)
		return ErrInvalidRequest, fmt.Errorf(msg)
	}

	return "", nil
}

// authContext attempts to return the authorization context from the payload.
// The second value returned is the error title, used to give more details to the user
// agent about the given error.
func (a *API) authContext(ctx context.Context, payload *ent.AuthorizationPayload, service *ent.Service) (AuthorizationContext, string, error) {
	if payload.ClientID == "" {
		msg := fmt.Sprintf("invalid request: missing client ID")
		a.Logger.Error(msg, "error", ErrInvalidRequest)
		return AuthorizationContext{}, ErrInvalidRequest, fmt.Errorf(msg)
	}
	app, err := a.getApplication(ctx, payload.ClientID)
	if ent.IsNotFound(err) {
		msg := fmt.Sprintf("invalid request: client ID not found")
		a.Logger.Error(msg, "error", ErrInvalidRequest, "client_id", payload.ClientID)
		return AuthorizationContext{}, ErrInvalidRequest, fmt.Errorf(msg)
	}
	if err != nil {
		msg := "server error: cannot get application"
		a.Logger.Error(msg, "error", ErrServerError, "client_id", payload.ClientID)
		return AuthorizationContext{}, ErrServerError, fmt.Errorf(msg)
	}

	errorTitle, err := a.validatePayload(payload, service, app)
	if err != nil {
		return AuthorizationContext{}, errorTitle, err
	}

	cfg, err := service.QueryServiceAuthorizationEndpointConfig().Only(ctx)
	if err != nil {
		msg := "server error: cannot get authorization endpoint config"
		a.Logger.Error(msg, "error", ErrServerError, "error_details", err)
		return AuthorizationContext{}, ErrServerError, fmt.Errorf(msg)
	}

	payload, err = enrichPayloadWithPKCEConfiguration(payload, app, cfg)
	if err != nil {
		msg := "invalid request: PKCE configuration error"
		a.Logger.Error(msg, "error", err)
		return AuthorizationContext{}, ErrInvalidRequest, err
	}

	grantedScopes, err := getGrantedScopes(payload.Scope, app.Scopes)
	if err != nil {
		msg := "invalid request: the requested scopes cannot be granted"
		a.Logger.Error(msg, "error", err)
		return AuthorizationContext{}, ErrInvalidRequest, fmt.Errorf(msg)
	}

	u, err := url.Parse(payload.RedirectURI)
	if err != nil {
		msg := "invalid request: invalid redirect URI"
		a.Logger.Error(msg, "error", err)
		return AuthorizationContext{}, ErrInvalidRequest, fmt.Errorf(msg)
	}

	return AuthorizationContext{
		Service:             service,
		Application:         app,
		CodeChallenge:       payload.CodeChallenge,
		CodeChallengeMethod: payload.CodeChallengeMethod,
		Nonce:               payload.Nonce,
		RedirectURI:         u,
		GrantedScopes:       strings.Split(grantedScopes, " "),
	}, "", nil
}

// callbackIsValid checks if the callback is valid.
func callbackIsValid(payload *ent.AuthorizationPayload, authCtx AuthorizationContext) bool {
	return contains(authCtx.Application.RedirectUris, payload.RedirectURI)
}

// authorizationFlow is the main flow for the authorization endpoint.
func (a *API) authorizationFlow(c echo.Context, service *ent.Service, payload *ent.AuthorizationPayload) error {
	// We are not following RFC6749 to the letter here, because according to the spec
	// when we fail to validate the request we should redirect the user agent back to the request URI.
	// However, this causes a number of issues: if the user makes a request
	// with a wrong client ID AND a wrong callback we can't tell the callback is not correct,
	// and any attempt at solving it caused a chicken-and-egg that pollutes the code.
	authCtx, errorTitle, err := a.authContext(c.Request().Context(), payload, service)
	if err != nil {
		return a.serveAuthFailedTemplate(c, errorTitle, err)
	}

	validCallback := callbackIsValid(payload, authCtx)
	if !validCallback {
		msg := fmt.Errorf("invalid request: invalid redirect URI: %s", payload.RedirectURI)
		a.Logger.Error(msg.Error(), "error", ErrInvalidRequest)
		return a.serveAuthFailedTemplate(c, ErrInvalidRequest, msg)
	}

	userContext, err := a.getUserContext(c)
	if err != nil {
		return a.initiateLoginFlow(c, service, payload)
	}
	if !userContext.IsAuthenticated() {
		return a.initiateLoginFlow(c, service, payload)
	}

	generatedCode, err := randomAlphanumericString(32)
	if err != nil {
		// This is serious, because it means we can't generate a random code.
		// Need to figure out how to test it
		msg := "server error: unable to generate code"
		a.Logger.Error(msg, "error", ErrServerError, "error_details", err.Error())
		return a.serveAuthFailedTemplate(c, ErrServerError, fmt.Errorf(msg))
	}

	switch payload.ResponseType {
	case ResponseTypeAuthorizationCode:
		v, err := a.handleResponseTypeAuthorizationCode(c.Request().Context(), authCtx, userContext, generatedCode, payload)
		if err != nil {
			msg := "server error: cannot create authorization code"
			a.Logger.Error(msg, "error", ErrServerError, "error_details", err.Error())
			return a.serveAuthFailedTemplate(c, ErrServerError, fmt.Errorf(msg))
		}
		// query is the default response mode for the authorization code response type
		switch payload.ResponseMode {
		case ResponseModeQuery:
			callback := fmt.Sprintf("%s?%s", payload.RedirectURI, v.Encode())
			return c.Redirect(http.StatusFound, callback)
		case ResponseModeFragment:
			callback := fmt.Sprintf("%s#%s", payload.RedirectURI, v.Encode())
			return c.Redirect(http.StatusFound, callback)
		default:
			callback := fmt.Sprintf("%s?%s", payload.RedirectURI, v.Encode())
			return c.Redirect(http.StatusFound, callback)
		}

	case ResponseTypeIDToken:
		v, errorTitle, err := a.handleResponseTypeIDToken(c.Request().Context(), authCtx, userContext, payload, "")
		if err != nil {
			return a.serveAuthFailedTemplate(c, errorTitle, err)
		}

		// fragment is the default response mode for the id token response type
		switch payload.ResponseMode {
		case ResponseModeQuery:
			callback := fmt.Sprintf("%s?%s", authCtx.RedirectURI.String(), v.Encode())
			return c.Redirect(http.StatusFound, callback)
		case ResponseModeFragment:
			callback := fmt.Sprintf("%s#%s", authCtx.RedirectURI.String(), v.Encode())
			return c.Redirect(http.StatusFound, callback)
		default:
			callback := fmt.Sprintf("%s#%s", authCtx.RedirectURI.String(), v.Encode())
			return c.Redirect(http.StatusFound, callback)
		}
	case ResponseTypeCodeIDToken:
		// OIDC Hybrid Flow
		// Return both an authorization code and an ID token
		// in the authorization response
		v, err := a.handleResponseTypeAuthorizationCode(c.Request().Context(), authCtx, userContext, generatedCode, payload)
		if err != nil {
			msg := "server error: cannot create authorization code"
			a.Logger.Error(msg, "error", ErrServerError, "error_details", err.Error())
			return a.serveAuthFailedTemplate(c, ErrServerError, fmt.Errorf(msg))
		}
		idURLValues, errorTitle, err := a.handleResponseTypeIDToken(c.Request().Context(), authCtx, userContext, payload, generatedCode)
		if err != nil {
			return a.serveAuthFailedTemplate(c, errorTitle, err)
		}
		v.Set("id_token", idURLValues.Get("id_token"))
		// fragment is the default response mode for the `code id token` response type
		switch payload.ResponseMode {
		case ResponseModeQuery:
			callback := fmt.Sprintf("%s?%s", payload.RedirectURI, v.Encode())
			return c.Redirect(http.StatusFound, callback)
		case ResponseModeFragment:
			callback := fmt.Sprintf("%s#%s", payload.RedirectURI, v.Encode())
			return c.Redirect(http.StatusFound, callback)
		default:
			callback := fmt.Sprintf("%s#%s", payload.RedirectURI, v.Encode())
			return c.Redirect(http.StatusFound, callback)
		}

	default:
		// this should never happen, since we validate the response type
		msg := "server error: unsupported response type"
		a.Logger.Error(msg, "error", ErrServerError, "error_details", err.Error())
		return a.serveAuthFailedTemplate(c, msg, err)
	}
}

func (a *API) initiateLoginFlow(c echo.Context, service *ent.Service, payload *ent.AuthorizationPayload) error {
	id := uuid.New().String()
	s := &ent.Session{
		ID:          id,
		CreatedAt:   time.Now().Unix(),
		ServiceName: service.Name,
	}
	if err := a.createSession(c.Request().Context(), s, payload); err != nil {
		msg := "server error: cannot create session"
		a.Logger.Error(msg, "error", ErrServerError, "error_details", err.Error())
		return a.serveAuthFailedTemplate(c, ErrServerError, fmt.Errorf(msg))
	}

	loginConfig, err := service.QueryServiceLoginEndpointConfig().Only(c.Request().Context())
	if err != nil {
		msg := "server error: cannot get login endpoint config"
		a.Logger.Error(msg, "error", ErrServerError, "error_details", err)
		return a.serveAuthFailedTemplate(c, ErrServerError, fmt.Errorf(msg))
	}

	path := sanitiseEndpoint(loginConfig.Endpoint, a.BaseURL)
	location := fmt.Sprintf("%s/%s?%s=%s", a.BaseURL, path, SessionIDQueryParameter, id)
	a.Logger.Info("redirecting to login endpoint", "location", location, "session_id", id)
	fmt.Println("redirecting to login endpoint", location)
	return c.Redirect(http.StatusTemporaryRedirect, location)
}

// createSession creates a session.
func (a *API) createSession(ctx context.Context, s *ent.Session, payload *ent.AuthorizationPayload) error {
	_, err := a.DB.EntClient.AuthorizationPayload.Create().
		SetID(payload.ID).
		SetResponseType(payload.ResponseType).
		SetResponseMode(payload.ResponseMode).
		SetClientID(payload.ClientID).
		SetRedirectURI(payload.RedirectURI).
		SetScope(payload.Scope).
		SetState(payload.State).
		SetCodeChallenge(payload.CodeChallenge).
		SetCodeChallengeMethod(payload.CodeChallengeMethod).
		SetNonce(payload.Nonce).
		SetServiceName(payload.ServiceName).
		Save(ctx)
	if err != nil {
		return err
	}

	_, err = a.DB.EntClient.Session.Create().
		SetID(s.ID).
		SetCreatedAt(s.CreatedAt).
		SetServiceName(s.ServiceName).
		SetAuthorizationPayload(payload).
		Save(ctx)
	return err
}

// handleResponseTypeAuthorizationCode handles the authorization code response type.
func (a *API) handleResponseTypeAuthorizationCode(ctx context.Context, authCtx AuthorizationContext, userContext UserContext, generatedCode string, payload *ent.AuthorizationPayload) (url.Values, error) {
	code := &ent.AuthorizationCode{
		ID:                  generatedCode,
		Application:         authCtx.Application.Name,
		CodeChallenge:       authCtx.CodeChallenge,
		CodeChallengeMethod: authCtx.CodeChallengeMethod,
		CreatedAt:           time.Now(),
		AuthTime:            userContext.AuthTime(),
		RedirectURI:         authCtx.RedirectURI.String(),
		Nonce:               authCtx.Nonce,
		Service:             authCtx.Service.Name,
		State:               payload.State,
		Subject:             userContext.Subject,
		GrantedScopes:       strings.Join(authCtx.GrantedScopes, " "),
	}

	if err := a.createAuthorizationCode(ctx, code); err != nil {
		return url.Values{}, err
	}
	v := url.Values{}
	v.Set("code", generatedCode)
	v.Set("state", payload.State)
	return v, nil
}

// handleResponseTypeIDToken handles the id token response type. The second value returned is an
// optional error title used when rendering the template of the error page.
func (a *API) handleResponseTypeIDToken(ctx context.Context, authCtx AuthorizationContext, userContext UserContext, payload *ent.AuthorizationPayload, generatedCode string) (url.Values, string, error) {
	privateKey, keyID, err := a.lastPrivateKeyAndKeyID(ctx, authCtx.Service)
	if err != nil {
		msg := "server error: cannot issue refresh token"
		a.Logger.Error(msg, "error", ErrServerError, "error_details", err.Error())
		return url.Values{}, ErrServerError, fmt.Errorf(msg)
	}

	id := uuid.New().String()
	opts := idTokenOptions{
		ID:          id,
		Application: authCtx.Application,
		ClientID:    payload.ClientID,
		Service:     authCtx.Service,
		Scopes:      strings.Join(authCtx.GrantedScopes, " "),
		CreatedAt:   time.Now().Unix(),
		Nonce:       authCtx.Nonce,
		AuthTime:    userContext.AuthTime(),
		PrivateKey:  privateKey,
		KeyID:       keyID,
		Subject:     userContext.Subject,
		Code:        generatedCode,
	}
	token, err := a.issueIDToken(ctx, opts)
	if err != nil {
		msg := "server error: cannot issue refresh token"
		a.Logger.Error(msg, "error", ErrServerError, "error_details", err.Error())
		return url.Values{}, ErrServerError, fmt.Errorf(msg)
	}
	v := url.Values{}
	v.Set("id_token", token)
	v.Set("state", payload.State)
	return v, "", nil
}

// createAuthorizationCode creates an authorization code.
func (a *API) createAuthorizationCode(ctx context.Context, code *ent.AuthorizationCode) error {
	_, err := a.DB.EntClient.AuthorizationCode.Create().
		SetID(code.ID).
		SetApplication(code.Application).
		SetCodeChallenge(code.CodeChallenge).
		SetCodeChallengeMethod(code.CodeChallengeMethod).
		SetCreatedAt(code.CreatedAt).
		SetAuthTime(code.AuthTime).
		SetRedirectURI(code.RedirectURI).
		SetNonce(code.Nonce).
		SetService(code.Service).
		SetState(code.State).
		SetSubject(code.Subject).
		SetGrantedScopes(code.GrantedScopes).
		Save(ctx)
	return err
}
