package application

import "go.authbricks.com/bricks/config"

type Option func(*config.Application)

// New creates a new configuration with default values.
func New(name string, opts ...Option) config.Application {
	app := config.Application{
		Name:                            name,
		Public:                          false,
		PKCERequired:                    false,
		ResponseTypes:                   []string{config.ResponseTypeCode},
		GrantTypes:                      []string{config.GrantTypeAuthorizationCode},
		S256CodeChallengeMethodRequired: false,
	}
	for _, opt := range opts {
		opt(&app)
	}
	return app
}

// WithService sets the Service field.
func WithService(service string) Option {
	return func(a *config.Application) {
		a.Service = service
	}
}

// WithDescription sets the Description.
func WithDescription(description string) Option {
	return func(a *config.Application) {
		a.Description = description
	}
}

// IsPublic marks the application as public if set to true. By default, it is false.
func IsPublic(public bool) Option {
	return func(a *config.Application) {
		a.Public = public
	}
}

// WithPKCERequired forces the application to use PKCE if set to true. By default, it is false.
// PKCE is required for public clients.
func WithPKCERequired(required bool) Option {
	return func(a *config.Application) {
		a.PKCERequired = required
	}
}

// WithRedirectURIs sets the allowed RedirectURIs.
func WithRedirectURIs(redirectURIs ...string) Option {
	return func(a *config.Application) {
		a.RedirectURIs = redirectURIs
	}
}

// WithResponseTypes sets the allowed response types.
func WithResponseTypes(responseTypes ...string) Option {
	return func(a *config.Application) {
		a.ResponseTypes = responseTypes
	}
}

// WithGrantTypes sets the allowed grant types.
func WithGrantTypes(grantTypes ...string) Option {
	return func(a *config.Application) {
		a.GrantTypes = grantTypes
	}
}

// S256CodeChallengeMethodRequired forces the S256 flow during a PKCE flow.
// By default, it is set to false.
func S256CodeChallengeMethodRequired(required bool) Option {
	return func(a *config.Application) {
		a.S256CodeChallengeMethodRequired = required
	}
}

// WithAllowedAuthenticationMethods sets the allowed authentication methods.
func WithAllowedAuthenticationMethods(methods ...string) Option {
	return func(a *config.Application) {
		a.AllowedAuthenticationMethods = methods
	}
}

// WithScopes sets the allowed scopes.
func WithScopes(scopes ...string) Option {
	return func(a *config.Application) {
		a.Scopes = scopes
	}
}
