package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"go.authbricks.com/bricks/client"
	"go.authbricks.com/bricks/config"
	abcrypto "go.authbricks.com/bricks/crypto"
	"go.authbricks.com/bricks/ent"

	"github.com/hashicorp/cap/jwt"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

// clientCredentialsTokenSuccessTestCase is the test case when issuing a successful token
// during a `client_credentials` flow.
type clientCredentialsTokenSuccessTestCase struct {
	Name           string
	Payload        TokenPayload
	ExpectedScopes []string
	KeySet         jwt.KeySet
}

// clientCredentialsTokenErrorTestCase is the test case when getting an error response from the token endpoint
// during a `client_credentials` flow.
type clientCredentialsTokenErrorTestCase struct {
	Name          string
	Payload       TokenPayload
	ExpectedError string
}

// prepareClientSecretPostRequest is a helper function to
// build a request which will use the `client_secret_post` authentication method.
func prepareClientSecretPostRequest(t *testing.T, endpoint string, payload TokenPayload) *http.Request {
	v := url.Values{}
	v.Set("scope", payload.Scope)
	v.Set("client_id", payload.ClientID)
	v.Set("client_secret", payload.ClientSecret)
	v.Set("audience", payload.Audience)
	v.Set("grant_type", payload.GrantType)
	v.Set("state", payload.State)
	v.Set("code_verifier", payload.CodeVerifier)

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(v.Encode()))
	require.Nil(t, err)
	req.Header.Add(echo.HeaderContentType, echo.MIMEApplicationForm)
	return req
}

// prepareClientSecretBasicRequest is a helper function to
// build a request which will use the `client_secret_basic` authentication method.
func prepareClientSecretBasicRequest(t *testing.T, endpoint string, payload TokenPayload) *http.Request {
	v := url.Values{}
	v.Set("scope", payload.Scope)
	v.Set("audience", payload.Audience)
	v.Set("grant_type", payload.GrantType)
	v.Set("redirect_uri", payload.RedirectURI)
	v.Set("code", payload.Code)
	v.Set("state", payload.State)
	v.Set("code_verifier", payload.CodeVerifier)
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(v.Encode()))
	require.Nil(t, err)
	req.Header.Add(echo.HeaderContentType, echo.MIMEApplicationForm)
	req.SetBasicAuth(payload.ClientID, payload.ClientSecret)
	return req
}

// clientCredentialsTokenSuccessfulResponse asserts that a response to the token endpoint is successful
// and that the token has the format we expect.
func clientCredentialsTokenSuccessfulResponse(t *testing.T, req *http.Request, tc clientCredentialsTokenSuccessTestCase) {
	t.Helper()
	r, err := http.DefaultClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, r.StatusCode)
	require.Equal(t, "no-store", r.Header.Get(echo.HeaderCacheControl))
	require.Equal(t, "no-cache", r.Header.Get("Pragma"))

	u := NewUnmarshaler[TokenSuccessResponse](r.Body)
	tokenResponse, err := u.Unmarshal()
	require.Nil(t, err)
	fmt.Println(tokenResponse.AccessToken)
	require.ElementsMatch(t, tc.ExpectedScopes, strings.Split(tokenResponse.Scope, " "))
	claims, err := tc.KeySet.VerifySignature(context.Background(), tokenResponse.AccessToken)
	require.Nil(t, err)
	scopesInTheToken, ok := claims["scope"].(string)
	require.True(t, ok)
	require.ElementsMatch(t, tc.ExpectedScopes, strings.Split(scopesInTheToken, " "))
}

// getCredentials is an helper function to retrieve the credentials for the given application.
func getCredentials(t *testing.T, api TestAPI, application string) *ent.Credentials {
	t.Helper()
	c := client.New(api.API.DB)
	creds, err := c.GetCredentialsByApplication(context.Background(), application)
	require.Nil(t, err)
	require.NotEmpty(t, creds)
	return creds[0]
}

// getKeySet is an helper function to get a jwt.KeySet.
func getKeySet(t *testing.T, jwksEndpoint string) jwt.KeySet {
	t.Helper()
	ks, err := abcrypto.GetKeySetFromJWKSEndpoint(context.Background(), jwksEndpoint)
	require.Nil(t, err)
	return ks
}

func TestAPI_ClientCredentialsTokenSuccess(t *testing.T) {
	t.Helper()
	testAPI, cancel := NewTestAPI(t)
	defer cancel(t)
	testAPI.Run(t)

	tokenEndpoint := fmt.Sprintf("http://%s/m2m/oauth2/token", testAPI.Address)
	keySetEndpoint := fmt.Sprintf("http://%s/m2m/oauth2/jwks", testAPI.Address)

	notificationsCredentials := getCredentials(t, testAPI, "notifications")
	m2mKeySet := getKeySet(t, keySetEndpoint)

	aud := fmt.Sprintf("http://%s/m2m/", testAPI.Address)
	testCases := []clientCredentialsTokenSuccessTestCase{
		{
			Name: "Success requesting default scopes",
			Payload: TokenPayload{
				ClientID:     notificationsCredentials.ClientID,
				ClientSecret: notificationsCredentials.ClientSecret,
				Audience:     aud,
				GrantType:    GrantTypeClientCredentials,
			},
			ExpectedScopes: []string{"calendar:read", "calendar:update"},
			KeySet:         m2mKeySet,
		},
		{
			Name: "Success requesting a single scope",
			Payload: TokenPayload{
				Scope:        "calendar:read",
				ClientID:     notificationsCredentials.ClientID,
				ClientSecret: notificationsCredentials.ClientSecret,
				Audience:     aud,
				GrantType:    GrantTypeClientCredentials,
			},
			ExpectedScopes: []string{"calendar:read"},
			KeySet:         m2mKeySet,
		},
		{
			Name: "Success requesting multiple scopes",
			Payload: TokenPayload{
				Scope:        "calendar:read calendar:update",
				ClientID:     notificationsCredentials.ClientID,
				ClientSecret: notificationsCredentials.ClientSecret,
				Audience:     aud,
				GrantType:    GrantTypeClientCredentials,
			},
			ExpectedScopes: []string{"calendar:read", "calendar:update"},
			KeySet:         m2mKeySet,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			req := prepareClientSecretPostRequest(t, tokenEndpoint, tc.Payload)
			clientCredentialsTokenSuccessfulResponse(t, req, tc)

			req = prepareClientSecretBasicRequest(t, tokenEndpoint, tc.Payload)
			clientCredentialsTokenSuccessfulResponse(t, req, tc)
		})
	}
}

func TestAPI_ClientCredentialsTokenError(t *testing.T) {
	a, cancel := NewTestAPI(t)
	defer cancel(t)
	a.Run(t)

	tokenEndpoint := fmt.Sprintf("http://%s/m2m/oauth2/token", a.Address)
	creds := getCredentials(t, a, "notifications")
	require.NotEmpty(t, creds)
	wrongGrants := getCredentials(t, a, "helpdesk-application")

	aud := fmt.Sprintf("http://%s/m2m/", a.Address)
	testCases := []clientCredentialsTokenErrorTestCase{
		{
			Name: "unsupported grant type",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				GrantType:    "unsupported",
			},
			ExpectedError: ErrUnsupportedGrantType,
		},
		{
			Name: "invalid request - empty audience",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				Audience:     "",
				GrantType:    GrantTypeClientCredentials,
			},
			ExpectedError: ErrInvalidRequest,
		},
		{
			Name: "invalid request - invalid audience",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				Audience:     "not_exist",
				GrantType:    GrantTypeClientCredentials,
			},
			ExpectedError: ErrInvalidRequest,
		},
		{
			Name: "invalid request - not existing client id / secret",
			Payload: TokenPayload{
				ClientID:     "not_existing",
				ClientSecret: "not_existing",
				Audience:     aud,
				GrantType:    GrantTypeClientCredentials,
			},
			ExpectedError: ErrInvalidClient,
		},
		{
			Name: "invalid request - correct client id / wrong secret",
			Payload: TokenPayload{
				ClientID:     creds.ClientID,
				ClientSecret: "not_existing",
				Audience:     aud,
				GrantType:    GrantTypeClientCredentials,
			},
			ExpectedError: ErrInvalidClient,
		},
		{
			Name: "unauthorized client - this client attempts to make a request for the wrong audience",
			Payload: TokenPayload{
				ClientID:     wrongGrants.ClientID,
				ClientSecret: wrongGrants.ClientSecret,
				Audience:     aud,
				GrantType:    GrantTypeClientCredentials,
			},
			ExpectedError: ErrUnauthorizedClient,
		},
		{
			Name: "invalid scope - the client requests scopes it cannot be granted",
			Payload: TokenPayload{
				Scope:        "not_existing",
				ClientID:     creds.ClientID,
				ClientSecret: creds.ClientSecret,
				Audience:     aud,
				GrantType:    GrantTypeClientCredentials,
			},
			ExpectedError: ErrInvalidScope,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			// client_secret_post authentication method
			req := prepareClientSecretPostRequest(t, tokenEndpoint, tc.Payload)
			clientCredentialsTokenErrorResponse(t, req, tc)

			// client_secret_basic authentication method
			req = prepareClientSecretBasicRequest(t, tokenEndpoint, tc.Payload)
			clientCredentialsTokenErrorResponse(t, req, tc)
		})
	}
}

func TestAPI_ClientCredentials_AuthenticationMethods(t *testing.T) {
	a, cancel := NewTestAPI(t)
	defer cancel(t)
	a.Run(t)

	tokenEndpoint := fmt.Sprintf("http://%s/m2m/oauth2/token", a.Address)
	clientSecretPostCreds := getCredentials(t, a, "only-client-secret-post")
	require.NotEmpty(t, clientSecretPostCreds)

	clientSecretBasicCreds := getCredentials(t, a, "only-client-secret-basic")
	require.NotEmpty(t, clientSecretBasicCreds)

	testCases := []struct {
		Name           string
		Payload        TokenPayload
		ExpectedError  string
		UsedAuthMethod string
	}{
		{
			Name: "error - client is only allowed to use client_secret_post - it's using client_secret_basic",
			Payload: TokenPayload{
				ClientID:     clientSecretPostCreds.ClientID,
				ClientSecret: clientSecretPostCreds.ClientSecret,
				GrantType:    config.GrantTypeClientCredentials,
			},
			UsedAuthMethod: config.AuthenticationMethodClientSecretBasic,
			ExpectedError:  ErrInvalidRequest,
		},
		{
			Name: "error - client is only allowed to use client_secret_basic - it's using client_secret_post",
			Payload: TokenPayload{
				ClientID:     clientSecretBasicCreds.ClientID,
				ClientSecret: clientSecretBasicCreds.ClientSecret,
				GrantType:    config.GrantTypeClientCredentials,
			},
			UsedAuthMethod: config.AuthenticationMethodClientSecretPost,
			ExpectedError:  ErrInvalidRequest,
		},
		{
			Name: "error - client is using an invalid client id",
			Payload: TokenPayload{
				ClientID:     "invalid",
				ClientSecret: clientSecretPostCreds.ClientSecret,
				GrantType:    config.GrantTypeClientCredentials,
			},
			UsedAuthMethod: config.AuthenticationMethodClientSecretPost,
			ExpectedError:  ErrInvalidClient,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			// client_secret_post authentication method
			if tc.UsedAuthMethod == config.AuthenticationMethodClientSecretPost {
				req := prepareClientSecretPostRequest(t, tokenEndpoint, tc.Payload)
				r, err := http.DefaultClient.Do(req)
				require.Nil(t, err)
				require.Equal(t, http.StatusBadRequest, r.StatusCode)
				u := NewUnmarshaler[TokenErrorResponse](r.Body)
				tokenResponse, err := u.Unmarshal()
				require.Nil(t, err)
				require.Equal(t, tc.ExpectedError, tokenResponse.Error)
			}

			// client_secret_basic authentication method
			if tc.UsedAuthMethod == config.AuthenticationMethodClientSecretBasic {
				req := prepareClientSecretBasicRequest(t, tokenEndpoint, tc.Payload)
				r, err := http.DefaultClient.Do(req)
				require.Nil(t, err)
				require.Equal(t, http.StatusBadRequest, r.StatusCode)
				u := NewUnmarshaler[TokenErrorResponse](r.Body)
				tokenResponse, err := u.Unmarshal()
				require.Nil(t, err)
				require.Equal(t, tc.ExpectedError, tokenResponse.Error)
			}
		})
	}
}

// clientCredentialsTokenErrorResponse asserts that we receive an error from the token endpoint
// when making an invalid request during a `client_credentials` flow.
func clientCredentialsTokenErrorResponse(t *testing.T, req *http.Request, tc clientCredentialsTokenErrorTestCase) {
	t.Helper()
	r, err := http.DefaultClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, http.StatusBadRequest, r.StatusCode)
	u := NewUnmarshaler[TokenErrorResponse](r.Body)
	tokenResponse, err := u.Unmarshal()
	require.Nil(t, err)
	require.Equal(t, tc.ExpectedError, tokenResponse.Error)
}
