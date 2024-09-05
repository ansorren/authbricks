package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"go.authbricks.com/bricks/client"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestAPI_GETLoginHandler(t *testing.T) {
	t.Helper()
	testAPI, cancel := NewTestAPI(t)
	defer cancel(t)
	testAPI.Run(t)

	loginEndpoint := fmt.Sprintf("http://%s/login", testAPI.Address)
	location, err := firstGETLoginRequest(t, loginEndpoint)
	require.Nil(t, err)

	resp, err := loginRequestWithSessionID(t, location)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	buf := new(strings.Builder)
	_, err = io.Copy(buf, resp.Body)
	require.Nil(t, err)
	// check errors
	fmt.Println(buf.String())
}

func TestAPI_PostLogin_EmailPass(t *testing.T) {
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

	cfg := oauth2.Config{
		ClientID:     credentials.ClientID,
		ClientSecret: credentials.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("http://%s/oauth2/authorize", testAPI.Address),
			TokenURL: fmt.Sprintf("http://%s/oauth2/token", testAPI.Address),
		},
		RedirectURL: "http://localhost:8080/callback",
		Scopes:      []string{"openid"},
	}
	httpClient := http.Client{}
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// do not follow the redirect
		return testErrRedirect
	}
	codeVerifier, err := GeneratePKCECodeVerifier()
	require.Nil(t, err)
	codeChallenge := GeneratePKCECodeChallenge(codeVerifier)

	opts := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("nonce", "foo"),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
	}
	authorize := cfg.AuthCodeURL("state", opts...)
	resp, err := httpClient.Get(authorize)
	require.NotNil(t, err)
	var urlErr *url.Error
	ok := errors.As(err, &urlErr)
	require.True(t, ok)
	require.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	loginEndpoint, err := resp.Location()
	require.Nil(t, err)
	resp, err = loginRequestWithSessionID(t, loginEndpoint.String())
	require.Nil(t, err)

	payload := EmailPasswordPayload{
		Username: "toni",
		Password: "hunter2",
	}

	r, err := POSTLoginRequest(t, loginEndpoint.String(), payload, resp.Cookies())
	require.NotNil(t, err)
	require.Equal(t, http.StatusFound, r.StatusCode)
	location, err := r.Location()
	require.Nil(t, err)

	fmt.Println("location", location.String())
	fmt.Println("cookies", r.Cookies())
	resp, err = resumeAuthorization(t, location.String(), r.Cookies())
	require.NotNil(t, err)
	ok = errors.As(err, &urlErr)
	require.True(t, ok)
	require.Equal(t, http.StatusFound, resp.StatusCode)

	callback, err := resp.Location()
	require.Nil(t, err)

	query := callback.Query()
	code := query.Get("code")
	require.NotEmpty(t, code)

	opts = []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", "foo"),
		oauth2.SetAuthURLParam("state", "state"),
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	}
	token, err := cfg.Exchange(context.Background(), code, opts...)
	require.Nil(t, err)
	require.NotEmpty(t, token.AccessToken)
}

// resumeAuthorization is a helper function used to make a request to the resume authorization endpoint.
func resumeAuthorization(t *testing.T, endpoint string, cookies []*http.Cookie) (*http.Response, error) {
	t.Helper()
	c := http.Client{}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return testErrRedirect
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	require.Nil(t, err)

	fmt.Println("cookies in request", cookies)
	parsedURL, err := url.Parse(endpoint)
	require.Nil(t, err)
	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	jar.SetCookies(parsedURL, cookies)
	c.Jar = jar

	return c.Do(req)
}
