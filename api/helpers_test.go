package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"go.authbricks.com/bricks/ent"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

// assertTokenLifetime asserts the lifetime of the token is the one we expect.
func assertTokenLifetime(t *testing.T, claims map[string]interface{}, expectedLifetime time.Duration) {
	t.Helper()
	i, ok := claims["iat"]
	require.True(t, ok)
	iat, ok := i.(float64)
	require.True(t, ok)
	issuedAt := time.Unix(int64(iat*1e9), 0)

	exp, ok := claims["exp"]
	require.True(t, ok)
	e, ok := exp.(float64)
	require.True(t, ok)
	expNano := int64(e * 1e9)

	duration := time.Duration(expNano - issuedAt.Unix())
	require.Equal(t, expectedLifetime, duration)
}

// writeFile is a helper function to write a file.
func writeFile(t *testing.T, fileName string, data []byte) {
	t.Helper()
	err := os.WriteFile(fileName, data, 0o644)
	require.Nil(t, err)
}

// deleteFile is a helper function to delete a file.
func deleteFile(t *testing.T, fileName string) {
	t.Helper()
	err := os.RemoveAll(fileName)
	require.Nil(t, err)
}

// firstGETLoginRequest is a helper function used to make a first GET request to the login endpoint.
// This is used to redirect to the same page while setting a session ID. It returns the content of the
// Location header, which can be used in subsequent requests.
func firstGETLoginRequest(t *testing.T, endpoint string) (string, error) {
	t.Helper()
	client := http.Client{}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		// we do not really want to follow the redirect,
		// so we return immediately an error
		return testErrRedirect
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	require.Nil(t, err)
	resp, err := client.Do(req)
	var urlErr *url.Error
	ok := errors.As(err, &urlErr)
	require.True(t, ok)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	location, err := resp.Location()
	require.Nil(t, err)
	parts := strings.Split(location.String(), "=")
	require.Len(t, parts, 2)
	_, err = uuid.Parse(parts[1])
	require.Nil(t, err)
	return location.String(), nil
}

// loginRequestWithSessionID is a helper function used to make a  request to the login endpoint.
// The caller is responsible to provide an endpoint with a session ID.
// This is used to set the CSRF cookie in the response.
func loginRequestWithSessionID(t *testing.T, endpoint string) (*http.Response, error) {
	t.Helper()
	client := http.Client{}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	require.Nil(t, err)
	resp, err := client.Do(req)
	return resp, err
}

func TestSanitiseEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		baseURL  string
		expected string
	}{
		{
			name:     "Base URL prefix is removed",
			endpoint: "http://example.com/api/v1/resource",
			baseURL:  "http://example.com/",
			expected: "api/v1/resource",
		},
		{
			name:     "Leading slash is removed",
			endpoint: "/api/v1/resource",
			baseURL:  "http://example.com/",
			expected: "api/v1/resource",
		},
		{
			name:     "Multiple leading slashes are removed",
			endpoint: "///api/v1/resource",
			baseURL:  "http://example.com/",
			expected: "api/v1/resource",
		},
		{
			name:     "Base URL and leading slash are removed",
			endpoint: "http://example.com/api/v1/resource",
			baseURL:  "http://example.com/",
			expected: "api/v1/resource",
		},
		{
			name:     "Base URL and trailing slash are removed",
			endpoint: "http://example.com//api/v1/resource/",
			baseURL:  "http://example.com/",
			expected: "api/v1/resource",
		},
		{
			name:     "Multiple trailing slashes are removed",
			endpoint: "/api/v1/resource//",
			baseURL:  "http://example.com/",
			expected: "api/v1/resource",
		},
		{
			name:     "No base URL and no leading slash",
			endpoint: "api/v1/resource",
			baseURL:  "http://example.com/",
			expected: "api/v1/resource",
		},
		{
			name:     "Base URL does not match",
			endpoint: "http://other.com/api/v1/resource",
			baseURL:  "http://example.com/",
			expected: "http://other.com/api/v1/resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := sanitiseEndpoint(tt.endpoint, tt.baseURL)
			if actual != tt.expected {
				t.Errorf("sanitiseEndpoint(%q, %q) = %q; expected %q", tt.endpoint, tt.baseURL, actual, tt.expected)
			}
		})
	}
}

// extractCSRFCookieValue returns the value of the CSRF cookie.
func extractCSRFCookieValue(cookies []*http.Cookie) string {
	for _, cookie := range cookies {
		if cookie.Name == "_csrf" {
			return cookie.Value
		}
	}
	return ""
}

// POSTLoginRequest is a helper function used to make a POST request to the login endpoint.
// It also sets the CSRF cookie in the request.
func POSTLoginRequest(t *testing.T, endpoint string, payload EmailPasswordPayload, cookies []*http.Cookie) (*http.Response, error) {
	t.Helper()
	// set the CSRF cookie in the cookie jar
	client := http.Client{}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		// we do not really want to follow the redirect,
		// so we return immediately an error
		return testErrRedirect
	}

	parsedURL, err := url.Parse(endpoint)
	require.Nil(t, err)
	fmt.Println("parsed url", parsedURL.String())
	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	jar.SetCookies(parsedURL, cookies)
	client.Jar = jar

	csrf := extractCSRFCookieValue(cookies)
	fmt.Println("executing POST request to login endpoint", endpoint)

	// make a POST request to the login endpoint
	b, err := json.Marshal(payload)
	require.Nil(t, err)
	body := bytes.NewReader(b)
	req, err := http.NewRequest(http.MethodPost, endpoint, body)
	require.Nil(t, err)
	req.Header.Add(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Add(echo.HeaderXCSRFToken, csrf)

	resp, err := client.Do(req)
	return resp, err
}

// testRandomState is a helper function to generate a random state.
func testRandomState(t *testing.T) string {
	t.Helper()
	state, err := generateRandomState()
	require.Nil(t, err)
	require.NotEmpty(t, state)
	return state
}

func TestSessionIsExpired(t *testing.T) {
	testCases := []struct {
		name     string
		session  *ent.Session
		duration time.Duration
		now      time.Time
		expected bool
	}{
		{
			name: "Session just created, not expired",
			session: &ent.Session{
				CreatedAt: time.Now().Unix(),
			},
			duration: 24 * time.Hour,
			now:      time.Now(),
			expected: false,
		},
		{
			name: "Session about to expire, not yet expired",
			session: &ent.Session{
				CreatedAt: time.Now().Add(-23 * time.Hour).Unix(),
			},
			duration: 24 * time.Hour,
			now:      time.Now(),
			expected: false,
		},
		{
			name: "Session expired",
			session: &ent.Session{
				CreatedAt: time.Now().Add(-25 * time.Hour).Unix(),
			},
			duration: 24 * time.Hour,
			now:      time.Now(),
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := sessionIsExpired(tc.session, tc.duration, tc.now)
			require.Equal(t, tc.expected, result)
		})
	}
}
