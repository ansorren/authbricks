package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.authbricks.com/bricks/ent"

	"github.com/hashicorp/cap/jwt"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

// authorizationCodeTokenErrorTestCase is the test case when sending a
// wrong request to the token error endpoint using the `authorization_code` flow.
type authorizationCodeTokenErrorTestCase struct {
	Name                 string
	Payload              TokenPayload
	Code                 *ent.AuthorizationCode
	ExpectedError        string
	ExpectedResponseCode int
}

func TestAPI_AuthorizationCodeTokenFlow_Error(t *testing.T) {
	a, cancel := NewTestAPI(t)
	defer cancel(t)
	a.Run(t)

	creds := getCredentials(t, a, "login-application")
	require.NotEmpty(t, creds)

	publicCreds := getCredentials(t, a, "public-client")
	require.NotEmpty(t, publicCreds)

	s256Required := getCredentials(t, a, "s256-required")
	require.NotEmpty(t, s256Required)

	employeesLoginAppCreds := getCredentials(t, a, "employees-login-application")
	require.NotEmpty(t, employeesLoginAppCreds)

	helpdeskAppCreds := getCredentials(t, a, "helpdesk-application")
	require.NotEmpty(t, helpdeskAppCreds)

	// vars for PKCE testing
	codeVerifier, err := GeneratePKCECodeVerifier()
	require.Nil(t, err)
	codeChallenge := GeneratePKCECodeChallenge(codeVerifier)
	wrongVerifier, err := GeneratePKCECodeVerifier()
	require.Nil(t, err)
	wrongCodeChallenge := GeneratePKCECodeChallenge(wrongVerifier)
	tooShortCodeVerifier := "too_short"
	tooLongCodeVerifier := strings.Repeat("a", 129)

	// vars for authorization code expiration logic
	twoHoursAgo := time.Now().Add(-time.Hour * 2)
	oneSecondAgo := time.Now().Add(-time.Second * 1)

	tokenEndpoint := fmt.Sprintf("http://%s/customers/oauth2/token", a.Address)

	testCases := []authorizationCodeTokenErrorTestCase{
		{
			Name: "invalid request: client ID not provided",
			Payload: TokenPayload{
				ClientID:     "",
				ClientSecret: creds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				State:        "correct_state",
			},
			Code: &ent.AuthorizationCode{
				ID:    "1",
				State: "correct_state",
			},
			ExpectedError:        ErrInvalidRequest,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			Name: "invalid request: authorization code not provided",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				State:        "correct_state",
				Code:         "",
			},
			Code: &ent.AuthorizationCode{
				ID:    "2",
				State: "correct_state",
			},
			ExpectedError:        ErrInvalidRequest,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			Name: "invalid request: state not provided",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				State:        "",
				Code:         "3",
			},
			Code: &ent.AuthorizationCode{
				ID:    "3",
				State: "correct_state",
			},
			ExpectedError:        ErrInvalidRequest,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			// invalid client ID
			Name: "invalid client: not found",
			Payload: TokenPayload{
				ClientID:     "invalid",
				ClientSecret: creds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				State:        "correct_state",
				Code:         "4",
			},
			Code: &ent.AuthorizationCode{
				ID:    "4",
				State: "correct_state",
			},
			ExpectedError:        ErrInvalidClient,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			// invalid client secret
			Name: "invalid request: invalid credentials",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: "invalid",
				GrantType:    GrantTypeAuthorizationCode,
				State:        "correct_state",
				Code:         "5",
			},
			Code: &ent.AuthorizationCode{
				ID:    "5",
				State: "correct_state",
			},
			ExpectedError:        ErrInvalidRequest,
			ExpectedResponseCode: http.StatusUnauthorized,
		},
		{
			Name: "invalid request: invalid code",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				State:        "correct_state",
				Code:         "invalid",
			},
			Code: &ent.AuthorizationCode{
				ID:    "6",
				State: "correct_state",
			},
			ExpectedError:        ErrInvalidRequest,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			Name: "invalid grant: expired authorization code",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				State:        "correct_state",
				Code:         "7",
			},
			Code: &ent.AuthorizationCode{
				ID:        "7",
				State:     "correct_state",
				CreatedAt: twoHoursAgo,
			},
			ExpectedError:        ErrInvalidGrant,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			Name: "invalid request: invalid state",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				State:        "invalid",
				Code:         "8",
			},
			Code: &ent.AuthorizationCode{
				ID:        "8",
				State:     "correct_state",
				CreatedAt: oneSecondAgo,
			},
			ExpectedError:        ErrInvalidRequest,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			// valid code but for a different client
			Name: "invalid grant: invalid code",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				State:        "correct_state",
				Code:         "9",
			},
			Code: &ent.AuthorizationCode{
				ID:          "9",
				State:       "correct_state",
				CreatedAt:   oneSecondAgo,
				Application: "wrong_application",
			},
			ExpectedError:        ErrInvalidGrant,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			// code verifier: too short
			Name: "invalid request: code verifier is too short - must be at least 43 characters",
			Payload: TokenPayload{
				ClientID:     publicCreds.ClientID,
				ClientSecret: publicCreds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				State:        "correct_state",
				Code:         "10",
				CodeVerifier: tooShortCodeVerifier,
			},
			Code: &ent.AuthorizationCode{
				ID:                  "10",
				State:               "correct_state",
				CodeChallengeMethod: PKCECodeChallengeMethodS256,
				Application:         "public-client",
				CreatedAt:           oneSecondAgo,
			},
			ExpectedError:        ErrInvalidRequest,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			// code verifier: too long
			Name: "invalid request: code verifier is too long - must be 128 characters max",
			Payload: TokenPayload{
				ClientID:     publicCreds.ClientID,
				ClientSecret: publicCreds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				State:        "correct_state",
				Code:         "11",
				CodeVerifier: tooLongCodeVerifier,
			},
			Code: &ent.AuthorizationCode{
				ID:                  "11",
				State:               "correct_state",
				CodeChallengeMethod: PKCECodeChallengeMethodS256,
				Application:         "public-client",
				CreatedAt:           oneSecondAgo,
				CodeChallenge:       GeneratePKCECodeChallenge(tooLongCodeVerifier),
			},
			ExpectedError:        ErrInvalidRequest,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			// PKCE: plain - verifier must match challenge
			Name: "invalid request: invalid code verifier - code challenge method: plain",
			Payload: TokenPayload{
				ClientID:     publicCreds.ClientID,
				ClientSecret: publicCreds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				State:        "correct_state",
				Code:         "12",
				CodeVerifier: codeVerifier,
			},
			Code: &ent.AuthorizationCode{
				ID:                  "12",
				State:               "correct_state",
				CodeChallengeMethod: PKCECodeChallengeMethodPlain,
				Application:         "public-client",
				CreatedAt:           oneSecondAgo,
				CodeChallenge:       "mismatch",
			},
			ExpectedError:        ErrInvalidRequest,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			// PKCE: S256 - mismatch between code challenge and verifier
			Name: "invalid request: invalid code verifier - code challenge method: S256",
			Payload: TokenPayload{
				ClientID:     publicCreds.ClientID,
				ClientSecret: publicCreds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				State:        "correct_state",
				Code:         "13",
				CodeVerifier: codeVerifier,
			},
			Code: &ent.AuthorizationCode{
				ID:                  "13",
				State:               "correct_state",
				CodeChallengeMethod: PKCECodeChallengeMethodS256,
				Application:         "public-client",
				CreatedAt:           oneSecondAgo,
				CodeChallenge:       wrongCodeChallenge,
			},
			ExpectedError:        ErrInvalidRequest,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			// PKCE: S256 - invalid code challenge method
			Name: "invalid request: invalid code challenge method: wrong_method",
			Payload: TokenPayload{
				ClientID:     publicCreds.ClientID,
				ClientSecret: publicCreds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				State:        "correct_state",
				Code:         "13",
				CodeVerifier: codeVerifier,
			},
			Code: &ent.AuthorizationCode{
				ID:                  "13",
				State:               "correct_state",
				CodeChallengeMethod: "wrong_method",
				Application:         "public-client",
				CreatedAt:           oneSecondAgo,
				CodeChallenge:       codeChallenge,
			},
			ExpectedError:        ErrInvalidRequest,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			// PKCE: application requires S256 but the client is using plain
			Name: "invalid request: plain code challenge method not allowed",
			Payload: TokenPayload{
				ClientID:     s256Required.ClientID,
				ClientSecret: s256Required.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				State:        "correct_state",
				Code:         "13",
				CodeVerifier: codeVerifier,
			},
			Code: &ent.AuthorizationCode{
				ID:                  "13",
				State:               "correct_state",
				CodeChallengeMethod: PKCECodeChallengeMethodPlain,
				Application:         "s256-required",
				CreatedAt:           oneSecondAgo,
				CodeChallenge:       codeVerifier,
			},
			ExpectedError:        ErrInvalidRequest,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			Name: "invalid grant: redirect URI mismatch",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				State:        "correct_state",
				Code:         "14",
				RedirectURI:  "https://example.com/wrong_callback",
			},
			Code: &ent.AuthorizationCode{
				ID:          "14",
				State:       "correct_state",
				Application: "login-application",
				CreatedAt:   oneSecondAgo,
				RedirectURI: "https://example.com/callback",
			},
			ExpectedError:        ErrInvalidGrant,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			Name: "invalid request: service does not match",
			Payload: TokenPayload{
				ClientID:     employeesLoginAppCreds.ClientID,
				ClientSecret: employeesLoginAppCreds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				State:        "correct_state",
				Code:         "15",
				RedirectURI:  "https://example.com/callback",
			},
			Code: &ent.AuthorizationCode{
				ID:          "15",
				State:       "correct_state",
				Application: "employees-login-application",
				CreatedAt:   oneSecondAgo,
				RedirectURI: "https://example.com/callback",
				Service:     "employees",
			},
			ExpectedError:        ErrInvalidRequest,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			Name: "invalid grant: authorization code not bound to the service",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				State:        "correct_state",
				Code:         "16",
				RedirectURI:  "https://example.com/callback",
			},
			Code: &ent.AuthorizationCode{
				ID:          "16",
				State:       "correct_state",
				Application: "login-application",
				Service:     "employees",
				CreatedAt:   oneSecondAgo,
				RedirectURI: "https://example.com/callback",
			},
			ExpectedError:        ErrInvalidGrant,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			Name: "unauthorized client: authorization code grant type not allowed",
			Payload: TokenPayload{
				ClientID:     helpdeskAppCreds.ClientID,
				ClientSecret: helpdeskAppCreds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				State:        "correct_state",
				Code:         "17",
				RedirectURI:  "https://example.com/callback",
			},
			Code: &ent.AuthorizationCode{
				ID:          "17",
				State:       "correct_state",
				Application: "helpdesk-application",
				Service:     "customers",
				CreatedAt:   oneSecondAgo,
				RedirectURI: "https://example.com/callback",
			},
			ExpectedError:        ErrUnauthorizedClient,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			Name: "invalid request: invalid redirect URI",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				State:        "correct_state",
				Code:         "18",
				RedirectURI:  "https://example.com/wrong_callback",
			},
			Code: &ent.AuthorizationCode{
				ID:          "18",
				State:       "correct_state",
				Application: "login-application",
				Service:     "customers",
				CreatedAt:   oneSecondAgo,
				RedirectURI: "https://example.com/wrong_callback",
			},
			ExpectedError:        ErrInvalidRequest,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			// the scope passed in the payload is not present in the
			// granted scopes of the authorization code
			Name: "invalid scope: cannot grant the requested scopes",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				State:        "correct_state",
				Code:         "18",
				RedirectURI:  "http://localhost:8080/callback",
				Scope:        "invalid_scope",
			},
			Code: &ent.AuthorizationCode{
				ID:            "18",
				State:         "correct_state",
				Application:   "login-application",
				Service:       "customers",
				CreatedAt:     oneSecondAgo,
				RedirectURI:   "http://localhost:8080/callback",
				GrantedScopes: "openid profile email",
			},
			ExpectedError:        ErrInvalidScope,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			// the application is not allowed to use the requested scopes
			// because the service does not allow it, although the
			// authorization code has granted it
			Name: "invalid scope: cannot grant the requested scopes",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				State:        "correct_state",
				Code:         "19",
				RedirectURI:  "http://localhost:8080/callback",
				Scope:        "not_allowed_by_the_service",
			},
			Code: &ent.AuthorizationCode{
				ID:            "19",
				State:         "correct_state",
				Application:   "login-application",
				Service:       "customers",
				CreatedAt:     oneSecondAgo,
				RedirectURI:   "http://localhost:8080/callback",
				GrantedScopes: "not_allowed_by_the_service",
			},
			ExpectedError:        ErrInvalidScope,
			ExpectedResponseCode: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			_, err := a.API.DB.EntClient.AuthorizationCode.Create().
				SetID(tc.Code.ID).
				SetApplication(tc.Code.Application).
				SetCodeChallenge(tc.Code.CodeChallenge).
				SetCodeChallengeMethod(tc.Code.CodeChallengeMethod).
				SetCreatedAt(tc.Code.CreatedAt).
				SetAuthTime(tc.Code.AuthTime).
				SetRedirectURI(tc.Code.RedirectURI).
				SetNonce(tc.Code.Nonce).
				SetService(tc.Code.Service).
				SetState(tc.Code.State).
				SetSubject(tc.Code.Subject).
				SetGrantedScopes(tc.Code.GrantedScopes).
				Save(context.Background())
			require.Nil(t, err)
			req := prepareClientSecretBasicRequest(t, tokenEndpoint, tc.Payload)
			authorizationCodeTokenErrorResponse(t, req, tc)
			_ = a.API.DB.EntClient.AuthorizationCode.DeleteOneID(tc.Code.ID).Exec(context.Background())
		})
	}
}

// authorizationCodeTokenErrorResponse asserts that we receive the expected error from the token endpoint
// when making an invalid request during an `authorization_code` flow.
func authorizationCodeTokenErrorResponse(t *testing.T, req *http.Request, tc authorizationCodeTokenErrorTestCase) {
	t.Helper()
	r, err := http.DefaultClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, tc.ExpectedResponseCode, r.StatusCode)
	u := NewUnmarshaler[TokenErrorResponse](r.Body)
	tokenResponse, err := u.Unmarshal()
	require.Nil(t, err)
	require.Equal(t, tc.ExpectedError, tokenResponse.Error)
	require.Equal(t, tc.Name, tokenResponse.ErrorDescription)
}

func TestAPI_AuthorizationCodeTokenFlow_Success(t *testing.T) {
	a, cancel := NewTestAPI(t)
	defer cancel(t)
	a.Run(t)

	creds := getCredentials(t, a, "login-application")
	require.NotEmpty(t, creds)

	oneMinuteAgo := time.Now().Add(-1 * time.Minute)
	tokenEndpoint := fmt.Sprintf("http://%s/customers/oauth2/token", a.Address)

	customerJWKS := fmt.Sprintf("http://%s/customers/oauth2/jwks", a.Address)
	customerKeySet := getKeySet(t, customerJWKS)

	// PKCE code verifier
	codeVerifier, err := GeneratePKCECodeVerifier()
	require.Nil(t, err)
	codeChallenge := GeneratePKCECodeChallenge(codeVerifier)

	testCases := []authorizationCodeTokenSuccessTestCase{
		{
			Name: "Success requesting default scopes",
			Payload: TokenPayload{
				Scope:        "",
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				RedirectURI:  "http://localhost:8080/callback",
				Code:         "successful_code_1",
				State:        "correct_state",
			},
			Code: &ent.AuthorizationCode{
				ID:            "successful_code_1",
				Application:   "login-application",
				RedirectURI:   "http://localhost:8080/callback",
				CreatedAt:     oneMinuteAgo,
				Service:       "customers",
				State:         "correct_state",
				Nonce:         "correct_nonce",
				Subject:       "foo",
				GrantedScopes: "openid profile email offline_access",
			},
			ExpectedAccessTokenLifetime: 24 * time.Hour,
			ExpectedIDToken:             true,
			ExpectedRefreshToken:        true,
			ExpectedScopes:              []string{"openid", "profile", "email", "offline_access"},
			KeySet:                      customerKeySet,
		},
		{
			Name: "Success using PKCE / S256 code challenge method",
			Payload: TokenPayload{
				Scope:        "",
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				RedirectURI:  "http://localhost:8080/callback",
				Code:         "successful_code_2",
				State:        "correct_state",
				CodeVerifier: codeVerifier,
			},
			Code: &ent.AuthorizationCode{
				ID:                  "successful_code_2",
				Application:         "login-application",
				RedirectURI:         "http://localhost:8080/callback",
				CreatedAt:           oneMinuteAgo,
				Service:             "customers",
				State:               "correct_state",
				CodeChallenge:       codeChallenge,
				CodeChallengeMethod: PKCECodeChallengeMethodS256,
				Nonce:               "correct_nonce",
				Subject:             "foo",
				GrantedScopes:       "openid profile email offline_access",
			},
			ExpectedAccessTokenLifetime: 24 * time.Hour,
			ExpectedIDToken:             true,
			ExpectedRefreshToken:        true,
			ExpectedScopes:              []string{"openid", "profile", "email", "offline_access"},
			KeySet:                      customerKeySet,
		},
		{
			Name: "Success using PKCE / plain code challenge method",
			Payload: TokenPayload{
				Scope:        "",
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				RedirectURI:  "http://localhost:8080/callback",
				Code:         "successful_code_2",
				State:        "correct_state",
				CodeVerifier: codeVerifier,
			},
			Code: &ent.AuthorizationCode{
				ID:                  "successful_code_2",
				Application:         "login-application",
				RedirectURI:         "http://localhost:8080/callback",
				CreatedAt:           oneMinuteAgo,
				Service:             "customers",
				State:               "correct_state",
				CodeChallenge:       codeVerifier,
				CodeChallengeMethod: PKCECodeChallengeMethodPlain,
				Nonce:               "correct_nonce",
				Subject:             "foo",
				GrantedScopes:       "openid profile email offline_access",
			},
			ExpectedAccessTokenLifetime: 24 * time.Hour,
			ExpectedIDToken:             true,
			ExpectedRefreshToken:        true,
			ExpectedScopes:              []string{"openid", "profile", "email", "offline_access"},
			KeySet:                      customerKeySet,
		},
		{
			Name: "Success without requesting an ID token",
			Payload: TokenPayload{
				Scope:        "",
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				RedirectURI:  "http://localhost:8080/callback",
				Code:         "successful_code_3",
				State:        "correct_state",
			},
			Code: &ent.AuthorizationCode{
				ID:            "successful_code_3",
				Application:   "login-application",
				RedirectURI:   "http://localhost:8080/callback",
				CreatedAt:     oneMinuteAgo,
				Service:       "customers",
				State:         "correct_state",
				Nonce:         "correct_nonce",
				Subject:       "foo",
				GrantedScopes: "profile email offline_access",
			},
			ExpectedAccessTokenLifetime: 24 * time.Hour,
			ExpectedIDToken:             false,
			ExpectedRefreshToken:        true,
			ExpectedScopes:              []string{"profile", "email", "offline_access"},
			KeySet:                      customerKeySet,
		},
		{
			Name: "Success without requesting a refresh token",
			Payload: TokenPayload{
				Scope:        "",
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    GrantTypeAuthorizationCode,
				RedirectURI:  "http://localhost:8080/callback",
				Code:         "successful_code_4",
				State:        "correct_state",
			},
			Code: &ent.AuthorizationCode{
				ID:            "successful_code_4",
				Application:   "login-application",
				RedirectURI:   "http://localhost:8080/callback",
				CreatedAt:     oneMinuteAgo,
				Service:       "customers",
				State:         "correct_state",
				Nonce:         "correct_nonce",
				Subject:       "foo",
				GrantedScopes: "openid profile email",
			},
			ExpectedAccessTokenLifetime: 24 * time.Hour,
			ExpectedIDToken:             true,
			ExpectedRefreshToken:        false,
			ExpectedScopes:              []string{"openid", "profile", "email"},
			KeySet:                      customerKeySet,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			_, err := a.API.DB.EntClient.AuthorizationCode.Create().
				SetID(tc.Code.ID).
				SetApplication(tc.Code.Application).
				SetCodeChallenge(tc.Code.CodeChallenge).
				SetCodeChallengeMethod(tc.Code.CodeChallengeMethod).
				SetCreatedAt(tc.Code.CreatedAt).
				SetAuthTime(tc.Code.AuthTime).
				SetRedirectURI(tc.Code.RedirectURI).
				SetNonce(tc.Code.Nonce).
				SetService(tc.Code.Service).
				SetState(tc.Code.State).
				SetSubject(tc.Code.Subject).
				SetGrantedScopes(tc.Code.GrantedScopes).
				Save(context.Background())
			require.Nil(t, err)
			req := prepareClientSecretBasicRequest(t, tokenEndpoint, tc.Payload)
			authorizationCodeTokenSuccessResponse(t, req, tc)

			_ = a.API.DB.EntClient.AuthorizationCode.DeleteOneID(tc.Code.ID).Exec(context.Background())

		})
	}
}

// authorizationCodeTokenSuccessTestCase is the test case when sending a
// correct request to the token endpoint using the `authorization_code` flow.
type authorizationCodeTokenSuccessTestCase struct {
	Name                        string
	Payload                     TokenPayload
	Code                        *ent.AuthorizationCode
	ExpectedScopes              []string
	KeySet                      jwt.KeySet
	ExpectedAccessTokenLifetime time.Duration
	ExpectedRefreshToken        bool
	ExpectedIDToken             bool
}

func authorizationCodeTokenSuccessResponse(t *testing.T, req *http.Request, tc authorizationCodeTokenSuccessTestCase) {
	t.Helper()
	r, err := http.DefaultClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, r.StatusCode)
	require.Equal(t, "no-store", r.Header.Get(echo.HeaderCacheControl))
	require.Equal(t, "no-cache", r.Header.Get("Pragma"))

	u := NewUnmarshaler[TokenSuccessResponse](r.Body)
	tokenResponse, err := u.Unmarshal()
	require.Nil(t, err)
	require.ElementsMatch(t, tc.ExpectedScopes, strings.Split(tokenResponse.Scope, " "))
	fmt.Println(tokenResponse.AccessToken)
	claims, err := tc.KeySet.VerifySignature(context.Background(), tokenResponse.AccessToken)
	require.Nil(t, err)
	scopesInTheToken, ok := claims["scope"].(string)
	require.True(t, ok)
	require.ElementsMatch(t, tc.ExpectedScopes, strings.Split(scopesInTheToken, " "))

	// the `aud` claim should be the client ID
	audiences, ok := claims["aud"].([]interface{})
	require.True(t, ok)
	a, ok := audiences[0].(string)
	require.True(t, ok)
	require.Equal(t, tc.Payload.ClientID, a)

	assertTokenLifetime(t, claims, tc.ExpectedAccessTokenLifetime)

	if tc.ExpectedRefreshToken {
		require.NotEmpty(t, tokenResponse.RefreshToken)
	}
	if !tc.ExpectedRefreshToken {
		require.Empty(t, tokenResponse.RefreshToken)
	}

	if tc.ExpectedIDToken {
		require.NotEmpty(t, tokenResponse.IDToken)
	}
	if !tc.ExpectedIDToken {
		require.Empty(t, tokenResponse.IDToken)
	}
}
