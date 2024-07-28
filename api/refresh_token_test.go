package api

import (
	"context"
	"crypto"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"go.authbricks.com/bricks/config"
	abcrypto "go.authbricks.com/bricks/crypto"
	"go.authbricks.com/bricks/ent"
	"go.authbricks.com/bricks/ent/application"
	"go.authbricks.com/bricks/ent/service"

	"github.com/google/uuid"
	"github.com/hashicorp/cap/jwt"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

// refreshTokenTestCase is the test case for the refresh token flow.
type refreshTokenTestCase struct {
	Name                        string
	Payload                     TokenPayload
	Opts                        refreshTokenOptions
	ExpectedError               string
	ExpectedResponseCode        int
	ExpectedIDToken             bool
	KeySet                      jwt.KeySet
	ExpectedAccessTokenLifetime time.Duration
	Service                     *ent.Service
}

func TestAPI_RefreshToken(t *testing.T) {
	a, cancel := NewTestAPI(t)
	defer cancel(t)
	a.Run(t)

	tokenEndpoint := fmt.Sprintf("http://%s/customers/oauth2/token", a.API.Address)
	creds := getCredentials(t, a, "login-application")
	require.NotEmpty(t, creds)

	notificationCreds := getCredentials(t, a, "notifications")
	require.NotEmpty(t, notificationCreds)

	loginApplication, err := a.API.DB.EntClient.Application.Query().Where(application.Name("login-application")).Only(context.Background())
	require.Nil(t, err)
	notificationsApplication, err := a.API.DB.EntClient.Application.Query().Where(application.Name("notifications")).Only(context.Background())
	require.Nil(t, err)
	testApplication, err := a.API.DB.EntClient.Application.Query().Where(application.Name("test-application")).Only(context.Background())
	require.Nil(t, err)

	customersService, err := a.API.DB.EntClient.Service.Query().Where(service.Name("customers")).Only(context.Background())
	require.Nil(t, err)
	employeesService, err := a.API.DB.EntClient.Service.Query().Where(service.Name("employees")).Only(context.Background())
	require.Nil(t, err)

	oneMinuteAgo := time.Now().Add(-1 * time.Minute)
	twoDaysAgo := time.Now().Add(-48 * time.Hour)

	lastKey, keyID, err := a.API.lastPrivateKeyAndKeyID(context.Background(), customersService)
	require.Nil(t, err)

	// generate a key that isn't associated with any OAuth servers
	anotherRandomKey, err := abcrypto.GenerateRSAPrivateKey()
	require.Nil(t, err)

	testCases := []refreshTokenTestCase{
		{
			Name: "invalid client: not found",
			Payload: TokenPayload{
				ClientID:  "wrong",
				GrantType: config.GrantTypeRefreshToken,
			},
			Opts: refreshTokenOptions{
				ID:            uuid.New().String(),
				Application:   loginApplication,
				Service:       customersService,
				Scopes:        "openid profile offline_access",
				AccessTokenID: "some-access-token-id",
				CreatedAt:     oneMinuteAgo.Unix(),
				PrivateKey:    lastKey,
				KeyID:         keyID,
			},
			ExpectedError:        ErrInvalidClient,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			// notifications application is not allowed to issue refresh tokens
			// because it doesn't have a refresh token grant type.
			Name: "invalid grant: cannot issue refresh token",
			Payload: TokenPayload{
				ClientID:     notificationCreds.ClientID,
				ClientSecret: notificationCreds.ClientSecret,
				GrantType:    config.GrantTypeRefreshToken,
			},
			Opts: refreshTokenOptions{
				ID:            uuid.New().String(),
				Application:   notificationsApplication,
				Service:       customersService,
				Scopes:        "openid profile offline_access",
				AccessTokenID: "some-access-token-id",
				CreatedAt:     oneMinuteAgo.Unix(),
				PrivateKey:    lastKey,
				KeyID:         keyID,
			},
			ExpectedError:        ErrInvalidGrant,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			// invalid scopes - attempting to request non-existing
			// scopes
			Name: "invalid scope: the requested scopes cannot be granted",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    config.GrantTypeRefreshToken,
				Scope:        "non-existing",
			},
			Opts: refreshTokenOptions{
				ID:          uuid.New().String(),
				Application: loginApplication,
				Service:     customersService,
				PrivateKey:  lastKey,
				KeyID:       keyID,
				CreatedAt:   oneMinuteAgo.Unix(),
				Subject:     uuid.New().String(),
			},
			ExpectedError:        ErrInvalidScope,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			// no `offline_access` scope
			Name: "invalid grant: cannot issue refresh token",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    config.GrantTypeRefreshToken,
				Scope:        "openid profile",
			},
			Opts: refreshTokenOptions{
				ID:          uuid.New().String(),
				Application: loginApplication,
				Service:     customersService,
				PrivateKey:  lastKey,
				KeyID:       keyID,
				CreatedAt:   oneMinuteAgo.Unix(),
				Subject:     uuid.New().String(),
			},
			ExpectedError:        ErrInvalidGrant,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			// signing the refresh token with a random key that doesn't belong
			// to the OAuth server should trigger an error
			Name: "invalid request: cannot decrypt token",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    config.GrantTypeRefreshToken,
			},
			Opts: refreshTokenOptions{
				ID:          uuid.New().String(),
				Application: loginApplication,
				Service:     customersService,
				Scopes:      "openid profile offline_access",
				PrivateKey:  anotherRandomKey,
				KeyID:       uuid.New().String(),
				CreatedAt:   oneMinuteAgo.Unix(),
			},
			ExpectedError:        ErrInvalidRequest,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			// token valid for a different application
			Name: "invalid request: invalid refresh token",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    config.GrantTypeRefreshToken,
				Scope:        "openid profile offline_access",
			},
			Opts: refreshTokenOptions{
				ID:          uuid.New().String(),
				Application: testApplication,
				Service:     customersService,
				PrivateKey:  lastKey,
				KeyID:       keyID,
				CreatedAt:   oneMinuteAgo.Unix(),
				Subject:     uuid.New().String(),
			},
			ExpectedError:        ErrInvalidRequest,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			// token valid for a different service
			Name: "invalid request: invalid refresh token",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    config.GrantTypeRefreshToken,
				Scope:        "openid profile offline_access",
			},
			Opts: refreshTokenOptions{
				ID:          uuid.New().String(),
				Application: loginApplication,
				Service:     employeesService,
				PrivateKey:  lastKey,
				KeyID:       keyID,
				CreatedAt:   oneMinuteAgo.Unix(),
				Subject:     uuid.New().String(),
			},
			ExpectedError:        ErrInvalidRequest,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			// expired refresh token
			Name: "invalid request: invalid refresh token",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    config.GrantTypeRefreshToken,
				Scope:        "openid profile offline_access",
			},
			Opts: refreshTokenOptions{
				ID:          uuid.New().String(),
				Application: loginApplication,
				Service:     customersService,
				PrivateKey:  lastKey,
				KeyID:       keyID,
				CreatedAt:   twoDaysAgo.Unix(),
				Subject:     uuid.New().String(),
			},
			ExpectedError:        ErrInvalidRequest,
			ExpectedResponseCode: http.StatusBadRequest,
		},
		{
			// valid request with ID token
			// the `openid` scope is required to issue an ID token
			Name: "valid request with ID token",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    config.GrantTypeRefreshToken,
				Scope:        "openid profile offline_access",
			},
			Opts: refreshTokenOptions{
				ID:          uuid.New().String(),
				Application: loginApplication,
				Service:     customersService,
				PrivateKey:  lastKey,
				KeyID:       keyID,
				CreatedAt:   oneMinuteAgo.Unix(),
				Subject:     uuid.New().String(),
				Scopes:      "openid profile offline_access",
				AuthTime:    time.Now(),
			},
			ExpectedResponseCode: http.StatusOK,
			ExpectedIDToken:      true,
		},
		{
			// valid request without ID token
			// no `openid` scope
			Name: "valid request (without ID token)",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    config.GrantTypeRefreshToken,
				Scope:        "profile offline_access",
			},
			Opts: refreshTokenOptions{
				ID:          uuid.New().String(),
				Application: loginApplication,
				Service:     customersService,
				PrivateKey:  lastKey,
				KeyID:       keyID,
				CreatedAt:   oneMinuteAgo.Unix(),
				Subject:     uuid.New().String(),
				Scopes:      "profile offline_access",
				AuthTime:    time.Now(),
			},
			ExpectedResponseCode: http.StatusOK,
			ExpectedIDToken:      false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			// create a refresh token
			token, err := a.API.issueRefreshToken(context.Background(), tc.Opts)
			require.Nil(t, err)
			defer func() {
				_ = a.API.deleteRefreshToken(context.Background(), tc.Opts.ID)
			}()

			// create a request
			req := prepareRefreshTokenRequest(t, tokenEndpoint, tc.Payload, token)

			// execute the request
			resp, err := http.DefaultClient.Do(req)
			require.Nil(t, err)
			assertRefreshTokenResponse(t, resp, tc)
		})
	}
}

// decryptRefreshToken is an helper function that decrypts the refresh token using the given private key.
func decryptRefreshToken(t *testing.T, token string, key crypto.PrivateKey) *ent.RefreshToken {
	decrypted, err := abcrypto.DecryptWithKey(key, token)
	require.Nil(t, err)
	u := NewUnmarshaler[*ent.RefreshToken](strings.NewReader(decrypted))
	d, err := u.Unmarshal()
	require.Nil(t, err)
	return d
}

// assertRefreshTokenResponse asserts the response of the refresh token endpoint matches the one that we expect.
func assertRefreshTokenResponse(t *testing.T, response *http.Response, tc refreshTokenTestCase) {
	t.Helper()
	require.Equal(t, tc.ExpectedResponseCode, response.StatusCode)
	switch tc.ExpectedResponseCode {
	case http.StatusOK:
		u := NewUnmarshaler[TokenSuccessResponse](response.Body)
		r, err := u.Unmarshal()
		require.Nil(t, err)
		require.NotEmpty(t, r.AccessToken)
		require.NotEmpty(t, r.RefreshToken)
		require.Equal(t, tc.Opts.Scopes, r.Scope)
		require.Equal(t, TokenTypeBearer, r.TokenType)

		if tc.ExpectedAccessTokenLifetime.Seconds() != 0 {
			require.Equal(t, int(tc.ExpectedAccessTokenLifetime.Seconds()), r.ExpiresIn)
		}

		// decrypt the refresh token
		d := decryptRefreshToken(t, r.RefreshToken, tc.Opts.PrivateKey)
		require.Equal(t, tc.Opts.Application.Name, d.Application)
		require.Equal(t, tc.Opts.Service.Name, d.Service)
		require.Equal(t, tc.Opts.Scopes, d.Scopes)
		require.NotEmpty(t, d.CreatedAt)
		require.NotEmpty(t, d.AccessTokenID)
		require.Equal(t, tc.Opts.KeyID, d.KeyID)
		require.Equal(t, tc.Opts.Subject, d.Subject)
		require.NotEmpty(t, d.AuthTime)

		if tc.ExpectedIDToken {
			require.NotEmpty(t, r.IDToken)
		}
		if !tc.ExpectedIDToken {
			require.Empty(t, r.IDToken)
		}
	default:
		u := NewUnmarshaler[TokenErrorResponse](response.Body)
		r, err := u.Unmarshal()
		require.Nil(t, err)
		require.Equal(t, tc.Name, r.ErrorDescription)
		require.Equal(t, tc.ExpectedError, r.Error)
	}
}

// prepareRefreshTokenRequest is a helper function to
// build a request to the token endpoint using the refresh token grant type.
func prepareRefreshTokenRequest(t *testing.T, endpoint string, payload TokenPayload, token string) *http.Request {
	v := url.Values{}
	v.Set("scope", payload.Scope)
	v.Set("audience", payload.Audience)
	v.Set("grant_type", payload.GrantType)
	v.Set("redirect_uri", payload.RedirectURI)
	v.Set("code", payload.Code)
	v.Set("state", payload.State)
	v.Set("code_verifier", payload.CodeVerifier)
	v.Set("refresh_token", token)
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(v.Encode()))
	require.Nil(t, err)
	req.Header.Add(echo.HeaderContentType, echo.MIMEApplicationForm)
	req.SetBasicAuth(payload.ClientID, payload.ClientSecret)
	return req
}
