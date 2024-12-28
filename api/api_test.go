package api

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"

	"go.authbricks.com/bricks/client"
	"go.authbricks.com/bricks/crypto"
	"go.authbricks.com/bricks/testutils"

	"github.com/hashicorp/go-hclog"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

type TestAPI struct {
	API     *API
	Address string
}

func NewTestAPI(t *testing.T) (TestAPI, func(t *testing.T)) {
	t.Helper()
	db, cancelDB := testutils.DB(t)

	c := client.New(db)

	address := testutils.LocalhostAddress()
	testCfg := testutils.NewTestConfig(t, address)
	for _, svc := range testCfg.Services {
		_, err := c.CreateService(context.Background(), svc)
		require.Nil(t, err)
	}
	for _, app := range testCfg.Applications {
		_, err := c.CreateApplication(context.Background(), app)
		require.Nil(t, err)
	}
	for _, cred := range testCfg.Credentials {
		_, err := c.CreateCredentials(context.Background(), cred)
		require.Nil(t, err)
	}

	logger := hclog.Default().Named("test")

	a, err := New(db, address,
		WithLogger(logger),
		WithBaseURL(fmt.Sprintf("http://%s", address)),
		WithTLSEnabled(false))
	require.Nil(t, err)

	cancel := func(*testing.T) {
		cancelDB(t)
		_ = a.Close()
	}

	return TestAPI{
		API:     a,
		Address: address,
	}, cancel
}

func (api TestAPI) Run(t *testing.T) {
	t.Helper()
	go func() {
		err := api.API.Run(context.Background())
		if err != nil && errors.Is(err, http.ErrServerClosed) {
			return
		}
	}()
	time.Sleep(1 * time.Second)
}

func TestAPI_Run(t *testing.T) {
	t.Helper()
	testAPI, cancel := NewTestAPI(t)
	defer cancel(t)
	testAPI.Run(t)
}

func TestAPI_Validate(t *testing.T) {
	tests := []struct {
		name        string
		api         API
		expectedErr error
	}{
		{
			name: "Valid - Cert and Key provided",
			api: API{
				TLSEnabled: true,
				Cert:       []byte("cert"),
				Key:        []byte("key"),
			},
			expectedErr: nil,
		},
		{
			name: "Valid - Cert and Key File Paths provided",
			api: API{
				TLSEnabled:          true,
				CertificateFilePath: "/path/to/cert",
				KeyFilePath:         "/path/to/key",
			},
			expectedErr: nil,
		},
		{
			name: "Invalid - Neither Cert nor File Paths provided",
			api: API{
				TLSEnabled: true,
			},
			expectedErr: errors.New("either the certificate and key or the certificate file path and key file path must be provided when TLS is enabled"),
		},
		{
			name: "Invalid - Cert provided but File Path mixed",
			api: API{
				TLSEnabled:          true,
				Cert:                []byte("cert"),
				Key:                 []byte("key"),
				CertificateFilePath: "/path/to/cert",
			},
			expectedErr: errors.New("do not mix direct certificates and file paths; provide either both certificates or both file paths"),
		},
		{
			name: "Invalid - Key provided but no Cert",
			api: API{
				TLSEnabled: true,
				Key:        []byte("key"),
			},
			expectedErr: errors.New("either the certificate and key or the certificate file path and key file path must be provided when TLS is enabled"),
		},
		{
			name: "Invalid - Cert File Path provided but no Key File Path",
			api: API{
				TLSEnabled:          true,
				CertificateFilePath: "/path/to/cert",
			},
			expectedErr: errors.New("either the certificate and key or the certificate file path and key file path must be provided when TLS is enabled"),
		},
		{
			name: "Invalid - invalid method on route",
			api: API{
				Routes: []Route{
					{
						Method: "INVALID",
						Path:   "/",
					},
				},
			},
			expectedErr: fmt.Errorf("invalid method: %s", "INVALID"),
		},
		{
			name: "Invalid - non-unique path on route",
			api: API{
				Routes: []Route{
					{
						Method: "GET",
						Path:   "/",
					},
					{
						Method: "GET",
						Path:   "/", // duplicate path
					},
				},
			},
			expectedErr: fmt.Errorf("not unique path: %s", "/"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.api.Validate()
			if err != nil && tt.expectedErr != nil {
				if err.Error() != tt.expectedErr.Error() {
					t.Errorf("expected error: %v, got: %v", tt.expectedErr, err)
				}
			} else if !errors.Is(err, tt.expectedErr) {
				t.Errorf("expected error: %v, got: %v", tt.expectedErr, err)
			}
		})
	}
}

func TestAPI_TLS(t *testing.T) {
	t.Helper()
	db, cancelDB := testutils.DB(t)

	c := client.New(db)

	address := testutils.LocalhostAddress()
	testCfg := testutils.NewTestConfig(t, address)
	for _, svc := range testCfg.Services {
		_, err := c.CreateService(context.Background(), svc)
		require.Nil(t, err)
	}
	for _, app := range testCfg.Applications {
		_, err := c.CreateApplication(context.Background(), app)
		require.Nil(t, err)
	}
	for _, cred := range testCfg.Credentials {
		_, err := c.CreateCredentials(context.Background(), cred)
		require.Nil(t, err)
	}

	logger := hclog.Default().Named("test")

	pemKey, err := crypto.NewRSA4096PEMKey()
	require.Nil(t, err)

	rsaKey, err := crypto.GetRSAKeyFromPEM(pemKey)
	require.Nil(t, err)

	oneYear := 365 * 24 * time.Hour

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.Nil(t, err)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ACME"},
			Country:      []string{"UK"},
			CommonName:   "authbricks.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(oneYear),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	cert, key, err := rsaKey.Certificate(template)
	require.Nil(t, err)

	a, err := New(db, address,
		WithLogger(logger),
		WithBaseURL(fmt.Sprintf("https://%s", address)),
		WithTLSEnabled(true),
		WithCertificate(cert),
		WithKey(key),
	)
	require.Nil(t, err)

	cancel := func(*testing.T) {
		cancelDB(t)
		_ = a.Close()
	}
	defer cancel(t)

	go func() {
		err := a.Run(context.Background())
		require.Nil(t, err)
	}()
	time.Sleep(1 * time.Second)

	// Skip TLS verification
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	resp, err := http.DefaultClient.Get(fmt.Sprintf("https://%s/", address))
	require.Nil(t, err)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPI_TLS_FilePath(t *testing.T) {
	t.Helper()
	db, cancelDB := testutils.DB(t)

	c := client.New(db)

	address := testutils.LocalhostAddress()
	testCfg := testutils.NewTestConfig(t, address)
	for _, svc := range testCfg.Services {
		_, err := c.CreateService(context.Background(), svc)
		require.Nil(t, err)
	}
	for _, app := range testCfg.Applications {
		_, err := c.CreateApplication(context.Background(), app)
		require.Nil(t, err)
	}
	for _, cred := range testCfg.Credentials {
		_, err := c.CreateCredentials(context.Background(), cred)
		require.Nil(t, err)
	}

	logger := hclog.Default().Named("test")

	pemKey, err := crypto.NewRSA4096PEMKey()
	require.Nil(t, err)

	rsaKey, err := crypto.GetRSAKeyFromPEM(pemKey)
	require.Nil(t, err)

	oneYear := 365 * 24 * time.Hour

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.Nil(t, err)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ACME"},
			Country:      []string{"UK"},
			CommonName:   "authbricks.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(oneYear),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	cert, key, err := rsaKey.Certificate(template)
	require.Nil(t, err)

	certFilePath := fmt.Sprintf("%s%s", os.TempDir(), "cert.pem")
	keyFilePath := fmt.Sprintf("%s%s", os.TempDir(), "/key.pem")

	writeFile(t, certFilePath, cert)
	writeFile(t, keyFilePath, key)

	defer func() {
		deleteFile(t, certFilePath)
		deleteFile(t, keyFilePath)
	}()

	a, err := New(db, address,
		WithLogger(logger),
		WithBaseURL(fmt.Sprintf("https://%s", address)),
		WithTLSEnabled(true),
		WithCertificateFilePath(certFilePath),
		WithKeyFilePath(keyFilePath),
	)
	require.Nil(t, err)

	cancel := func(*testing.T) {
		cancelDB(t)
		_ = a.Close()
	}
	defer cancel(t)

	go func() {
		err := a.Run(context.Background())
		require.Nil(t, err)
	}()
	time.Sleep(1 * time.Second)

	// Skip TLS verification
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	resp, err := http.DefaultClient.Get(fmt.Sprintf("https://%s/", address))
	require.Nil(t, err)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPI_Shutdown(t *testing.T) {
	a, cancel := NewTestAPI(t)
	defer cancel(t)
	a.Run(t)

	err := a.API.Shutdown(context.Background())
	require.Nil(t, err)
}

func TestAPI_WithRoutes(t *testing.T) {
	routes := []Route{
		{
			Method: http.MethodGet,
			Path:   "/custom",
			Handler: echo.HandlerFunc(func(c echo.Context) error {
				return c.JSON(http.StatusTeapot, "custom route")
			}),
			Middlewares: []echo.MiddlewareFunc{},
		},
		{
			Method: http.MethodGet,
			Path:   "/custom/with/middleware",
			Handler: echo.HandlerFunc(func(c echo.Context) error {
				return c.JSON(http.StatusTeapot, "custom route with middleware")
			}),
			Middlewares: []echo.MiddlewareFunc{
				middleware.BasicAuth(func(username, password string, c echo.Context) (bool, error) {
					if username == "toni" && password == "hunter2" {
						return true, nil
					}
					return false, nil
				}),
			},
		},
	}

	// do not use the test API, as we need to test the custom route
	// with the custom handler - rewrite the test to instantiate the API
	// directly

	db, cancelDB := testutils.DB(t)
	defer cancelDB(t)
	c := client.New(db)

	address := testutils.LocalhostAddress()
	testCfg := testutils.NewTestConfig(t, address)
	for _, svc := range testCfg.Services {
		_, err := c.CreateService(context.Background(), svc)
		require.Nil(t, err)
	}
	for _, app := range testCfg.Applications {
		_, err := c.CreateApplication(context.Background(), app)
		require.Nil(t, err)
	}
	for _, cred := range testCfg.Credentials {
		_, err := c.CreateCredentials(context.Background(), cred)
		require.Nil(t, err)
	}
	logger := hclog.Default().Named("test")

	a, err := New(db, address,
		WithLogger(logger),
		WithBaseURL(fmt.Sprintf("http://%s", address)),
		WithRoutes(routes),
	)
	require.Nil(t, err)

	go func() {
		_ = a.Run(context.Background())
	}()
	time.Sleep(1 * time.Second)

	resp, err := http.DefaultClient.Get(fmt.Sprintf("http://%s/custom", address))
	require.Nil(t, err)
	require.Equal(t, http.StatusTeapot, resp.StatusCode)

	// make a standard, unauthenticated request to the protected route
	// assert that the status code is 401
	resp, err = http.DefaultClient.Get(fmt.Sprintf("http://%s/custom/with/middleware", address))
	require.Nil(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// make an authenticated request to the protected route
	// but with the wrong credentials
	// assert that the status code is 401
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/custom/with/middleware", address), nil)
	require.Nil(t, err)
	req.SetBasicAuth("toni", "wrong-password")
	resp, err = http.DefaultClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// make an authenticated request to the protected route
	// assert that the status code is 418
	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/custom/with/middleware", address), nil)
	require.Nil(t, err)
	req.SetBasicAuth("toni", "hunter2")
	resp, err = http.DefaultClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, http.StatusTeapot, resp.StatusCode)
}
