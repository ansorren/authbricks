package api

import (
	"context"
	"fmt"
	"go.authbricks.com/bricks/client"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// testErrRedirect is a test error that is used to test the redirect behaviour.
var testErrRedirect = errors.New("redirect")

func TestAPI_AuthorizationHandler_Redirect(t *testing.T) {
	t.Helper()
	testAPI, cancel := NewTestAPI(t)
	defer cancel(t)
	testAPI.Run(t)

	state, err := generateRandomState()
	require.Nil(t, err)
	fmt.Println("state", state)

	creds := getCredentials(t, testAPI, "login-application")

	tokenEndpoint := fmt.Sprintf("http://%s/oauth2/token", testAPI.Address)
	authEndpoint := fmt.Sprintf("http://%s/oauth2/authorize", testAPI.Address)
	cfg := oauth2.Config{
		ClientID:     creds.ClientID,
		ClientSecret: creds.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: tokenEndpoint,
			AuthURL:  authEndpoint,
		},
		RedirectURL: "http://localhost:8080/callback",
	}

	authCodeURL := cfg.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("nonce", "foo"))
	req, err := http.NewRequest(http.MethodGet, authCodeURL, nil)
	require.Nil(t, err)

	c := &http.Client{}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// we do not really want to follow the redirect,
		// so we return immediately an error
		return testErrRedirect
	}

	resp, err := c.Do(req)
	var urlErr *url.Error
	ok := errors.As(err, &urlErr)
	require.True(t, ok)
	require.Equal(t, testErrRedirect, urlErr.Err)
	require.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	location, err := resp.Location()
	require.Nil(t, err)

	// assert we are getting redirected to the login endpoint
	// with the session ID as a query parameter
	expectedLocationPrefix := fmt.Sprintf("http://%s/login?%s=", testAPI.Address, SessionIDQueryParameter)
	require.True(t, strings.HasPrefix(location.String(), expectedLocationPrefix))

	// assert the found session ID is a UUID
	sessionID := strings.TrimPrefix(location.String(), expectedLocationPrefix)
	_, err = uuid.Parse(sessionID)
	require.Nil(t, err)
}

func TestAPI_AuthorizationHandler_Error(t *testing.T) {
	t.Helper()
	testAPI, cancel := NewTestAPI(t)
	defer cancel(t)
	testAPI.Run(t)
	c := client.New(testAPI.API.DB)
	require.NotNil(t, c)

	service, err := c.GetService(context.Background(), "test-service")
	require.Nil(t, err)

	// create a user
	u, err := c.CreateUser(context.Background(), client.CreateUserRequest{
		ConnectionType: client.ConnectionTypeEmailPassword,
		UserID:         uuid.New().String(),
		Username:       "toni",
		Password:       "hunter2",
		Service:        service,
	})
	require.Nil(t, err)
	require.NotNil(t, u)
	credentials := getCredentials(t, testAPI, "test-application")
	fmt.Println("credentials", credentials)

	publicClientCredentials := getCredentials(t, testAPI, "public-client")
	fmt.Println("publicClient", publicClientCredentials)

	codeVerifier, err := GeneratePKCECodeVerifier()
	require.Nil(t, err)
	codeChallenge := GeneratePKCECodeChallenge(codeVerifier)
	fmt.Println("codeChallenge", codeChallenge)

	testCases := []struct {
		Name               string
		State              string
		ClientID           string
		ClientSecret       string
		RedirectURI        string
		Scopes             []string
		Opts               []oauth2.AuthCodeOption
		ExpectedStatusCode int
		ExpectedError      string
	}{

		{
			Name:               "invalid request: missing client ID",
			State:              testRandomState(t),
			ExpectedStatusCode: http.StatusBadRequest,
			ExpectedError:      ErrInvalidRequest,
		},
		{
			Name:               "invalid request: client ID not found",
			ClientID:           "invalid-client-id",
			State:              testRandomState(t),
			ExpectedStatusCode: http.StatusBadRequest,
			ExpectedError:      ErrInvalidRequest,
		},
		{
			Name:  "invalid request: unsupported response type invalid",
			State: testRandomState(t),
			Opts: []oauth2.AuthCodeOption{
				oauth2.AccessTypeOffline,
				oauth2.SetAuthURLParam("response_type", "invalid"),
			},
			ClientID:           credentials.ClientID,
			ExpectedStatusCode: http.StatusBadRequest,
			ExpectedError:      ErrUnsupportedResponseType,
		},
		{
			Name:  "invalid request: unsupported response mode invalid",
			State: testRandomState(t),
			Opts: []oauth2.AuthCodeOption{
				oauth2.AccessTypeOffline,
				oauth2.SetAuthURLParam("response_mode", "invalid"),
			},
			ClientID:           credentials.ClientID,
			ExpectedStatusCode: http.StatusBadRequest,
			ExpectedError:      ErrInvalidRequest,
		},
		{
			Name:               "invalid request: missing state",
			ClientID:           credentials.ClientID,
			State:              "",
			ExpectedStatusCode: http.StatusBadRequest,
			ExpectedError:      ErrInvalidRequest,
		},
		{
			Name:     "invalid request: missing code challenge",
			ClientID: publicClientCredentials.ClientID,
			State:    testRandomState(t),
			Opts: []oauth2.AuthCodeOption{
				oauth2.AccessTypeOffline,
			},
			ExpectedStatusCode: http.StatusBadRequest,
			ExpectedError:      ErrInvalidRequest,
		},
		{
			Name:     "invalid request: unsupported code challenge method: invalid",
			ClientID: publicClientCredentials.ClientID,
			State:    testRandomState(t),
			Opts: []oauth2.AuthCodeOption{
				oauth2.AccessTypeOffline,
				oauth2.SetAuthURLParam("code_challenge", codeChallenge),
				oauth2.SetAuthURLParam("code_challenge_method", "invalid"),
			},
			ExpectedStatusCode: http.StatusBadRequest,
			ExpectedError:      ErrInvalidRequest,
		},
		{
			Name:     "invalid request: the requested scopes cannot be granted",
			ClientID: publicClientCredentials.ClientID,
			Opts: []oauth2.AuthCodeOption{
				oauth2.AccessTypeOffline,
				oauth2.SetAuthURLParam("code_challenge", codeChallenge),
				oauth2.SetAuthURLParam("code_challenge_method", PKCECodeChallengeMethodS256),
			},
			State:              testRandomState(t),
			RedirectURI:        "http://localhost:8080/callback",
			Scopes:             []string{"openid", "invalid-scope"},
			ExpectedStatusCode: http.StatusBadRequest,
			ExpectedError:      ErrInvalidRequest,
		},
		{
			// redirect URI can't be parsed
			Name:     "invalid request: invalid redirect URI",
			ClientID: publicClientCredentials.ClientID,
			Opts: []oauth2.AuthCodeOption{
				oauth2.AccessTypeOffline,
				oauth2.SetAuthURLParam("code_challenge", codeChallenge),
				oauth2.SetAuthURLParam("code_challenge_method", PKCECodeChallengeMethodS256),
			},
			State:              testRandomState(t),
			RedirectURI:        "http://%s:8080/invalid-callback",
			Scopes:             []string{"openid"},
			ExpectedStatusCode: http.StatusBadRequest,
			ExpectedError:      ErrInvalidRequest,
		},
		{
			// redirect URI can be parsed but it's not
			// in the list of allowed redirect URIs
			Name:     "invalid request: invalid redirect URI: http://localhost:8080/invalid-callback",
			ClientID: publicClientCredentials.ClientID,
			Opts: []oauth2.AuthCodeOption{
				oauth2.AccessTypeOffline,
				oauth2.SetAuthURLParam("code_challenge", codeChallenge),
				oauth2.SetAuthURLParam("code_challenge_method", PKCECodeChallengeMethodS256),
			},
			State:              testRandomState(t),
			RedirectURI:        "http://localhost:8080/invalid-callback",
			Scopes:             []string{"openid"},
			ExpectedStatusCode: http.StatusBadRequest,
			ExpectedError:      ErrInvalidRequest,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			// build the request to the authorization endpoint
			cfg := oauth2.Config{
				ClientID:     tc.ClientID,
				ClientSecret: tc.ClientSecret,
				Endpoint: oauth2.Endpoint{
					AuthURL:  fmt.Sprintf("http://%s/oauth2/authorize", testAPI.Address),
					TokenURL: fmt.Sprintf("http://%s/oauth2/token", testAPI.Address),
				},
				RedirectURL: tc.RedirectURI,
				Scopes:      tc.Scopes,
			}
			authCodeURL := cfg.AuthCodeURL(tc.State, tc.Opts...)
			req, err := http.NewRequest(http.MethodGet, authCodeURL, nil)
			require.Nil(t, err)
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			c := &http.Client{}
			c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				// we do not really want to follow the redirect,
				// so we return immediately an error
				return testErrRedirect
			}
			resp, err := c.Do(req)
			require.Nil(t, err)
			require.Equal(t, tc.ExpectedStatusCode, resp.StatusCode)
			require.NotNil(t, resp.Body)
			bodyBytes, err := io.ReadAll(resp.Body)
			require.Nil(t, err)
			htmlContent := string(bodyBytes)
			require.Contains(t, htmlContent, tc.ExpectedError)
			require.Contains(t, htmlContent, tc.Name)
		})
	}
}

func TestAPI_AuthorizationHandler_Success(t *testing.T) {
	t.Helper()
	testAPI, cancel := NewTestAPI(t)
	defer cancel(t)
	testAPI.Run(t)
	c := client.New(testAPI.API.DB)
	require.NotNil(t, c)

	// customer endpoint and credentials who don't need PKCE
	customerEndpoint := fmt.Sprintf("http://%s/customers/oauth2/authorize", testAPI.Address)
	credentials := getCredentials(t, testAPI, "login-application")
	fmt.Println("credentials", credentials)

	// public client endpoint and credentials who need PKCE
	endpoint := fmt.Sprintf("http://%s/oauth2/authorize", testAPI.Address)
	publicClientCredentials := getCredentials(t, testAPI, "public-client")
	fmt.Println("publicClient", publicClientCredentials)

	codeVerifier, err := GeneratePKCECodeVerifier()
	require.Nil(t, err)
	codeChallenge := GeneratePKCECodeChallenge(codeVerifier)
	fmt.Println("codeChallenge", codeChallenge)

	nonce := "foo"
	testCases := []struct {
		Name                        string
		Endpoint                    string
		State                       string
		ClientID                    string
		ClientSecret                string
		RedirectURI                 string
		Scopes                      []string
		Opts                        []oauth2.AuthCodeOption
		ExpectedStatusCode          int
		ExpectedServiceName         string
		ExpectedCodeChallenge       string
		ExpectedCodeChallengeMethod string
		ExpectedNonce               string
		ExpectedResponseType        string
		ExpectedResponseMode        string
	}{
		{
			Name:     "valid request with PKCE",
			Endpoint: endpoint,
			ClientID: publicClientCredentials.ClientID,
			Opts: []oauth2.AuthCodeOption{
				oauth2.AccessTypeOffline,
				oauth2.SetAuthURLParam("code_challenge", codeChallenge),
				oauth2.SetAuthURLParam("code_challenge_method", PKCECodeChallengeMethodS256),
				oauth2.SetAuthURLParam("nonce", nonce),
			},
			State:                       testRandomState(t),
			RedirectURI:                 "http://localhost:8080/callback",
			Scopes:                      []string{"openid"},
			ExpectedStatusCode:          http.StatusTemporaryRedirect,
			ExpectedServiceName:         "test-service",
			ExpectedCodeChallenge:       codeChallenge,
			ExpectedCodeChallengeMethod: PKCECodeChallengeMethodS256,
			ExpectedNonce:               nonce,
			ExpectedResponseType:        ResponseTypeAuthorizationCode,
			ExpectedResponseMode:        "",
		},
		{
			Name:     "valid request without PKCE",
			ClientID: credentials.ClientID,
			Endpoint: customerEndpoint,
			Opts: []oauth2.AuthCodeOption{
				oauth2.AccessTypeOffline,
				oauth2.SetAuthURLParam("nonce", nonce),
			},
			State:                       testRandomState(t),
			RedirectURI:                 "http://localhost:8080/callback",
			Scopes:                      []string{"openid"},
			ExpectedStatusCode:          http.StatusTemporaryRedirect,
			ExpectedServiceName:         "customers",
			ExpectedCodeChallenge:       "",
			ExpectedCodeChallengeMethod: "",
			ExpectedNonce:               nonce,
			ExpectedResponseType:        ResponseTypeAuthorizationCode,
			ExpectedResponseMode:        "",
		},
		{
			Name:     "valid request with response type id_token",
			ClientID: credentials.ClientID,
			Endpoint: customerEndpoint,
			Opts: []oauth2.AuthCodeOption{
				oauth2.AccessTypeOffline,
				oauth2.SetAuthURLParam("nonce", nonce),
				oauth2.SetAuthURLParam("response_type", ResponseTypeIDToken),
			},
			State:                       testRandomState(t),
			RedirectURI:                 "http://localhost:8080/callback",
			Scopes:                      []string{"openid"},
			ExpectedStatusCode:          http.StatusTemporaryRedirect,
			ExpectedServiceName:         "customers",
			ExpectedCodeChallenge:       "",
			ExpectedCodeChallengeMethod: "",
			ExpectedNonce:               nonce,
			ExpectedResponseType:        ResponseTypeIDToken,
			ExpectedResponseMode:        "",
		},
		{
			Name:     "valid request with response type code / response mode fragment",
			ClientID: credentials.ClientID,
			Endpoint: customerEndpoint,
			Opts: []oauth2.AuthCodeOption{
				oauth2.AccessTypeOffline,
				oauth2.SetAuthURLParam("nonce", nonce),
				oauth2.SetAuthURLParam("response_type", ResponseTypeAuthorizationCode),
				oauth2.SetAuthURLParam("response_mode", ResponseModeFragment),
			},
			State:                       testRandomState(t),
			RedirectURI:                 "http://localhost:8080/callback",
			Scopes:                      []string{"openid"},
			ExpectedStatusCode:          http.StatusTemporaryRedirect,
			ExpectedServiceName:         "customers",
			ExpectedCodeChallenge:       "",
			ExpectedCodeChallengeMethod: "",
			ExpectedNonce:               nonce,
			ExpectedResponseType:        ResponseTypeAuthorizationCode,
			ExpectedResponseMode:        ResponseModeFragment,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			// build the request to the authorization endpoint
			cfg := oauth2.Config{
				ClientID:     tc.ClientID,
				ClientSecret: tc.ClientSecret,
				Endpoint: oauth2.Endpoint{
					AuthURL: tc.Endpoint,
				},
				RedirectURL: tc.RedirectURI,
				Scopes:      tc.Scopes,
			}
			authCodeURL := cfg.AuthCodeURL(tc.State, tc.Opts...)
			fmt.Println("authCodeURL", authCodeURL)
			req, err := http.NewRequest(http.MethodGet, authCodeURL, nil)
			require.Nil(t, err)
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			c := &http.Client{}
			c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				// we do not really want to follow the redirect,
				// so we return immediately an error
				return testErrRedirect
			}
			resp, err := c.Do(req)
			require.NotNil(t, err)
			var urlErr *url.Error
			ok := errors.As(err, &urlErr)
			require.True(t, ok)
			require.Equal(t, tc.ExpectedStatusCode, resp.StatusCode)
			location, err := resp.Location()
			require.Nil(t, err)
			sessionID := location.Query().Get(SessionIDQueryParameter)
			sess, err := testAPI.API.DB.EntClient.Session.Get(context.Background(), sessionID)
			require.Nil(t, err)
			require.NotNil(t, sess)
			storedPayload, err := sess.QueryAuthorizationPayload().Only(context.Background())
			require.Nil(t, err)
			require.NotNil(t, storedPayload)

			// assert the stored payload is the same as the one we sent
			require.Equal(t, tc.State, storedPayload.State)
			require.Equal(t, tc.RedirectURI, storedPayload.RedirectURI)
			require.Equal(t, tc.Scopes, strings.Split(storedPayload.Scope, " "))
			require.Equal(t, tc.ClientID, storedPayload.ClientID)
			require.Equal(t, tc.ExpectedCodeChallenge, storedPayload.CodeChallenge)
			require.Equal(t, tc.ExpectedCodeChallengeMethod, storedPayload.CodeChallengeMethod)
			require.Equal(t, tc.ExpectedNonce, storedPayload.Nonce)
			require.Equal(t, tc.ExpectedServiceName, storedPayload.ServiceName)
			require.Equal(t, tc.ExpectedResponseType, storedPayload.ResponseType)
			require.Equal(t, tc.ExpectedResponseMode, storedPayload.ResponseMode)
		})
	}
}
