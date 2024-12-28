package api

import (
	"context"
	"encoding/gob"
	"fmt"
	"net/http"

	"go.authbricks.com/bricks/database"
	"go.authbricks.com/bricks/ent"

	"github.com/gorilla/sessions"
	"github.com/hashicorp/go-hclog"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/pkg/errors"
)

var (
	validAPIMethods = []string{
		http.MethodConnect,
		http.MethodDelete,
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
		http.MethodTrace,
	}
)

// API is the data structure used to represent the AuthBricks API.
type API struct {
	Address string
	DB      *database.DB
	Echo    *echo.Echo
	Logger  hclog.Logger
	BaseURL string
	Routes  []Route
	// TLS config
	TLSEnabled          bool
	Cert                []byte
	Key                 []byte
	CertificateFilePath string
	KeyFilePath         string
}

// Option is used to configure the API.
type Option func(*API)

// WithLogger sets the given logger on the API.
func WithLogger(logger hclog.Logger) Option {
	return func(a *API) {
		a.Logger = logger
	}
}

// WithBaseURL sets the base URL on the API.
func WithBaseURL(baseURL string) Option {
	return func(a *API) {
		a.BaseURL = baseURL
	}
}

// WithTLSEnabled enables TLS on the API.
func WithTLSEnabled(tlsEnabled bool) Option {
	return func(a *API) {
		a.TLSEnabled = tlsEnabled
	}
}

func WithCertificate(cert []byte) Option {
	return func(a *API) {
		a.Cert = cert
	}
}

func WithKey(key []byte) Option {
	return func(a *API) {
		a.Key = key
	}
}

// WithCertificateFilePath sets the certificate file path on the API.
func WithCertificateFilePath(certFilePath string) Option {
	return func(a *API) {
		a.CertificateFilePath = certFilePath
	}
}

// WithKeyFilePath sets the key file path on the API.
func WithKeyFilePath(keyFilePath string) Option {
	return func(a *API) {
		a.KeyFilePath = keyFilePath
	}
}

// WithRoutes sets the given custom routes on the API.
func WithRoutes(routes []Route) Option {
	return func(a *API) {
		a.Routes = routes
	}
}

// New returns a new API, which will be ready to run at the given address.
// It is the caller's responsibility to run the API by calling API.Run.
func New(db *database.DB, address string, opts ...Option) (*API, error) {
	if db == nil {
		return nil, errors.New("database is required, got nil pointer")
	}

	a := &API{
		DB:         db,
		Echo:       echo.New(),
		Logger:     hclog.Default(),
		TLSEnabled: false,
		BaseURL:    fmt.Sprintf("http://%s", address),
		Address:    address,
	}

	for _, opt := range opts {
		opt(a)
	}

	err := a.Validate()
	if err != nil {
		return nil, errors.Wrap(err, "failed to validate API configuration")
	}

	return a, nil
}

// Close closes the database connection.
func (a *API) Close() error {
	return a.DB.Close()
}

// Validate validates the API configuration.
func (a *API) Validate() error {
	if a.TLSEnabled {
		certProvided := len(a.Cert) > 0 && len(a.Key) > 0
		filePathProvided := a.CertificateFilePath != "" && a.KeyFilePath != ""

		if !certProvided && !filePathProvided {
			return errors.New("either the certificate and key or the certificate file path and key file path must be provided when TLS is enabled")
		}

		if certProvided && !filePathProvided && (a.CertificateFilePath != "" || a.KeyFilePath != "") {
			return errors.New("do not mix direct certificates and file paths; provide either both certificates or both file paths")
		}
	}

	if len(a.Routes) != 0 {
		for _, route := range a.Routes {
			if !contains(validAPIMethods, route.Method) {
				return fmt.Errorf("invalid method: %s", route.Method)
			}
			if !pathUnique(route.Path, a.Routes) {
				return fmt.Errorf("not unique path: %s", route.Path)
			}
		}
	}
	return nil
}

// Run runs the API server.
func (a *API) Run(ctx context.Context) error {
	a.Echo.Use(middleware.Recover())
	a.Echo.Use(middleware.Logger())
	csrfMiddleware := middleware.CSRF()
	a.Echo.Use(session.Middleware(sessions.NewCookieStore([]byte("secret"))))
	// register the user context, so that the sessions middleware can use it as a custom type.
	gob.Register(UserContext{})

	a.Echo.GET("/health", a.HealthHandler())

	services, err := a.getAllServices(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get services")
	}

	for _, service := range services {
		// register the service handlers
		// authorization endpoint
		auth, err := service.QueryServiceAuthorizationEndpointConfig().Only(ctx)
		if err != nil {
			return errors.Wrap(err, "failed to get service authorization endpoint config")
		}
		au := sanitiseEndpoint(auth.Endpoint, a.BaseURL)
		a.Echo.GET(au, a.AuthorizationHandler(service))
		a.Echo.GET(fmt.Sprintf("%s/resume", au), a.ResumeAuthorizationHandler(service))

		// token endpoint
		token, err := service.QueryServiceTokenEndpointConfig().Only(ctx)
		if err != nil {
			return errors.Wrap(err, "failed to get service token endpoint config")
		}
		t := sanitiseEndpoint(token.Endpoint, a.BaseURL)
		a.Echo.POST(t, a.TokenHandler(service))

		// introspection endpoint
		introspection, err := service.QueryServiceIntrospectionEndpointConfig().Only(ctx)
		if err != nil {
			return errors.Wrap(err, "failed to get service introspection endpoint config")
		}
		i := sanitiseEndpoint(introspection.Endpoint, a.BaseURL)
		a.Echo.POST(i, a.IntrospectionHandler(service))

		// userinfo endpoint
		userinfo, err := service.QueryServiceUserInfoEndpointConfig().Only(ctx)
		if err != nil {
			return errors.Wrap(err, "failed to get service userinfo endpoint config")
		}
		u := sanitiseEndpoint(userinfo.Endpoint, a.BaseURL)
		a.Echo.GET(u, a.UserInfoHandler(service))

		// jwks endpoint
		jwks, err := service.QueryServiceJwksEndpointConfig().Only(ctx)
		if err != nil {
			return errors.Wrap(err, "failed to get service jwks endpoint config")
		}
		j := sanitiseEndpoint(jwks.Endpoint, a.BaseURL)
		a.Echo.GET(j, a.JWKSHandler(service))

		// well known endpoint config
		wk, err := service.QueryServiceWellKnownEndpointConfig().Only(ctx)
		if err != nil {
			return errors.Wrap(err, "failed to get service well-known endpoint config")
		}
		w := sanitiseEndpoint(wk.Endpoint, a.BaseURL)
		a.Echo.GET(w, a.WellKnownHandler(service))

		// login endpoint
		login, err := service.QueryServiceLoginEndpointConfig().Only(ctx)
		if err != nil {
			return errors.Wrap(err, "failed to get service login endpoint config")
		}
		l := sanitiseEndpoint(login.Endpoint, a.BaseURL)
		a.Echo.GET(l, a.GETLoginHandler(service), csrfMiddleware)
		a.Echo.POST(l, a.POSTLoginHandler(service), csrfMiddleware)
	}

	for _, route := range a.Routes {
		a.Echo.Add(route.Method, route.Path, route.Handler, route.Middlewares...)
	}

	if a.TLSEnabled {
		// prioritise reading the cert / key directly,
		// if provided
		certProvided := len(a.Cert) > 0 && len(a.Key) > 0
		if certProvided {
			return a.Echo.StartTLS(a.Address, a.Cert, a.Key)
		}
		// read the file at the given path
		return a.Echo.StartTLS(a.Address, a.CertificateFilePath, a.KeyFilePath)
	}

	return a.Echo.Start(a.Address)
}

// Shutdown shuts down the server and closes the connection to the DB.
func (a *API) Shutdown(ctx context.Context) error {
	err := a.DB.Close()
	if err != nil {
		return errors.Wrapf(err, "unable to close DB connection")
	}

	return a.Echo.Shutdown(ctx)
}

// getAllServices returns all services.
func (a *API) getAllServices(ctx context.Context) ([]*ent.Service, error) {
	return a.DB.EntClient.Service.Query().All(ctx)
}
