package api

import (
	"context"
	"fmt"

	"go.authbricks.com/bricks/database"
	"go.authbricks.com/bricks/ent"

	"github.com/hashicorp/go-hclog"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/pkg/errors"
)

type API struct {
	Address    string
	DB         *database.DB
	Echo       *echo.Echo
	Logger     hclog.Logger
	TLSEnabled bool
	Cert       []byte
	Key        []byte
	BaseURL    string
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

	return a, nil
}

// Close closes the database connection.
func (a *API) Close() error {
	return a.DB.Close()
}

// Run runs the API server.
func (a *API) Run(ctx context.Context) error {
	a.Echo.Use(middleware.Recover())
	a.Echo.Use(middleware.Logger())

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
		a.Echo.GET(auth.Endpoint, a.AuthorizationHandler(service))

		// token endpoint
		token, err := service.QueryServiceTokenEndpointConfig().Only(ctx)
		if err != nil {
			return errors.Wrap(err, "failed to get service token endpoint config")
		}
		a.Echo.POST(token.Endpoint, a.TokenHandler(service))

		// introspection endpoint
		introspection, err := service.QueryServiceIntrospectionEndpointConfig().Only(ctx)
		if err != nil {
			return errors.Wrap(err, "failed to get service introspection endpoint config")
		}
		a.Echo.POST(introspection.Endpoint, a.IntrospectionHandler(service))

		// userinfo endpoint
		userinfo, err := service.QueryServiceUserInfoEndpointConfig().Only(ctx)
		if err != nil {
			return errors.Wrap(err, "failed to get service userinfo endpoint config")
		}
		a.Echo.GET(userinfo.Endpoint, a.UserInfoHandler(service))

		// jwks endpoint
		jwks, err := service.QueryServiceJwksEndpointConfig().Only(ctx)
		if err != nil {
			return errors.Wrap(err, "failed to get service jwks endpoint config")
		}
		a.Echo.GET(jwks.Endpoint, a.JWKSHandler(service))

		// well known endpoint config
		wk, err := service.QueryServiceWellKnownEndpointConfig().Only(ctx)
		if err != nil {
			return errors.Wrap(err, "failed to get service well-known endpoint config")
		}
		a.Echo.GET(wk.Endpoint, a.WellKnownHandler(service))
	}

	if a.TLSEnabled {
		return a.Echo.StartTLS(a.Address, string(a.Cert), string(a.Key))
	}

	return a.Echo.Start(a.Address)
}

// getAllServices returns all services.
func (a *API) getAllServices(ctx context.Context) ([]*ent.Service, error) {
	return a.DB.EntClient.Service.Query().All(ctx)
}
