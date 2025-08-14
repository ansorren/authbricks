package service

import (
	"crypto"
	"fmt"

	"go.authbricks.com/bricks/config"
)

type Option func(*config.Service)

// New creates a new configuration with default values.
func New(name string, opts ...Option) config.Service {
	service := config.Service{
		Name:          name,
		Scopes:        []string{"openid"},
		GrantTypes:    []string{config.GrantTypeAuthorizationCode},
		ResponseTypes: []string{config.ResponseTypeCode},
	}
	service.AuthorizationEndpoint = config.AuthorizationEndpoint{
		Endpoint:                        fmt.Sprintf("/%s/oauth2/authorize", name),
		PKCERequired:                    false,
		S256CodeChallengeMethodRequired: false,
	}
	service.IntrospectionEndpoint = config.IntrospectionEndpoint{
		Endpoint: fmt.Sprintf("/%s/oauth2/introspect", name),
	}
	service.TokenEndpoint = config.TokenEndpoint{
		Endpoint: fmt.Sprintf("/%s/oauth2/token", name),
		AllowedAuthenticationMethods: []string{
			config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost,
		},
	}
	service.UserInfoEndpoint = config.UserInfoEndpoint{
		Endpoint: fmt.Sprintf("/%s/oauth2/userinfo", name),
	}
	service.JWKSEndpoint = config.JWKSEndpoint{
		Endpoint: fmt.Sprintf("/%s/.well-known/jwks", name),
	}
	service.WellKnownEndpoint = config.WellKnownEndpoint{
		Endpoint: fmt.Sprintf("/%s/.well-known/openid-configuration", name),
	}
	service.LoginEndpoint = config.LoginEndpoint{
		Endpoint:       fmt.Sprintf("/%s/login", name),
		SessionTimeout: config.DefaultSessionTimeout,
	}

	for _, opt := range opts {
		opt(&service)
	}

	return service
}

// WithName sets the name.
func WithName(name string) Option {
	return func(s *config.Service) {
		s.Name = name
	}
}

// WithIdentifier sets the identifier.
func WithIdentifier(identifier string) Option {
	return func(s *config.Service) {
		s.Identifier = identifier
	}
}

// WithDescription sets the description.
func WithDescription(description string) Option {
	return func(s *config.Service) {
		s.Description = description
	}
}

// WithServiceMetadata sets the service metadata.
func WithServiceMetadata(metadata config.ServiceMetadata) Option {
	return func(s *config.Service) {
		s.ServiceMetadata = metadata
	}
}

// WithAllowedClientMetadata sets the allowed client metadata fields.
func WithAllowedClientMetadata(metadata ...string) Option {
	return func(s *config.Service) {
		s.AllowedClientMetadata = metadata
	}
}

// WithScopes sets the scopes.
func WithScopes(scopes ...string) Option {
	return func(s *config.Service) {
		s.Scopes = scopes
	}
}

// WithGrantTypes sets the grant types.
func WithGrantTypes(grantTypes ...string) Option {
	return func(s *config.Service) {
		s.GrantTypes = grantTypes
	}
}

// WithResponseTypes sets the response types.
func WithResponseTypes(responseTypes ...string) Option {
	return func(s *config.Service) {
		s.ResponseTypes = responseTypes
	}
}

// WithAuthorizationEndpoint sets the authorization endpoint configuration.
func WithAuthorizationEndpoint(endpoint config.AuthorizationEndpoint) Option {
	return func(s *config.Service) {
		s.AuthorizationEndpoint = endpoint
	}
}

// WithIntrospectionEndpoint sets the introspection endpoint configuration.
func WithIntrospectionEndpoint(endpoint config.IntrospectionEndpoint) Option {
	return func(s *config.Service) {
		s.IntrospectionEndpoint = endpoint
	}
}

// WithTokenEndpoint sets the token endpoint configuration.
func WithTokenEndpoint(endpoint config.TokenEndpoint) Option {
	return func(s *config.Service) {
		s.TokenEndpoint = endpoint
	}
}

// WithUserInfoEndpoint sets the user info endpoint configuration.
func WithUserInfoEndpoint(endpoint config.UserInfoEndpoint) Option {
	return func(s *config.Service) {
		s.UserInfoEndpoint = endpoint
	}
}

// WithJWKSEndpoint sets the JWKS endpoint configuration.
func WithJWKSEndpoint(endpoint config.JWKSEndpoint) Option {
	return func(s *config.Service) {
		s.JWKSEndpoint = endpoint
	}
}

// WithWellKnownEndpoint sets the well-known endpoint configuration.
func WithWellKnownEndpoint(endpoint config.WellKnownEndpoint) Option {
	return func(s *config.Service) {
		s.WellKnownEndpoint = endpoint
	}
}

// WithLoginEndpoint sets the login endpoint configuration.
func WithLoginEndpoint(endpoint config.LoginEndpoint) Option {
	return func(s *config.Service) {
		s.LoginEndpoint = endpoint
	}
}

// WithConnection sets the connection configuration.
func WithConnection(connection config.Connection) Option {
	return func(s *config.Service) {
		s.Connection = connection
	}
}

// WithKeys sets the private keys used to sign tokens.
func WithKeys(keys ...crypto.PrivateKey) Option {
	return func(s *config.Service) {
		s.Keys = keys
	}
}
