package config

import (
	"crypto"
	"crypto/rsa"
	"fmt"

	"github.com/pkg/errors"
)

const (
	// GrantTypeAuthorizationCode is the authorization code grant type.
	// See https://datatracker.ietf.org/doc/html/rfc6749#section-1.3.1
	GrantTypeAuthorizationCode = "authorization_code"
	// GrantTypeClientCredentials is the client credentials grant type.
	// See https://datatracker.ietf.org/doc/html/rfc6749#section-1.3.4
	GrantTypeClientCredentials = "client_credentials"
	// GrantTypeRefreshToken is the refresh token grant type.
	// See https://datatracker.ietf.org/doc/html/rfc6749#section-1.5
	GrantTypeRefreshToken = "refresh_token"
)

// AllowedGrantTypes is the list of allowed grant types.
var AllowedGrantTypes = []string{GrantTypeAuthorizationCode, GrantTypeClientCredentials, GrantTypeRefreshToken}

type ServiceMetadata map[string]string

// Service is used to configure a Service.
type Service struct {
	Name                  string
	Identifier            string
	Description           string
	ServiceMetadata       ServiceMetadata
	AllowedClientMetadata []string
	Scopes                []string
	GrantTypes            []string
	ResponseTypes         []string
	AuthorizationEndpoint AuthorizationEndpoint
	IntrospectionEndpoint IntrospectionEndpoint
	TokenEndpoint         TokenEndpoint
	UserInfoEndpoint      UserInfoEndpoint
	JWKSEndpoint          JWKSEndpoint
	WellKnownEndpoint     WellKnownEndpoint
	LoginEndpoint         LoginEndpoint
	Connection            Connection
	Keys                  []crypto.PrivateKey
}

// contains checks if the given string is in the given slice of strings.
func contains(slice []string, s string) bool {
	for _, a := range slice {
		if a == s {
			return true
		}
	}
	return false
}

// grantTypesAreAllowed checks if the given grant types are allowed.
func grantTypesAreAllowed(grantTypes []string) bool {
	for _, gt := range grantTypes {
		if !contains(AllowedGrantTypes, gt) {
			return false
		}
	}
	return true
}

// Validate validates the Service configuration.
func (s Service) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("service name is required")
	}
	if s.Identifier == "" {
		return fmt.Errorf("service identifier is required")
	}
	if len(s.Scopes) == 0 {
		return fmt.Errorf("at least one scope is required")
	}
	if len(s.GrantTypes) == 0 {
		return fmt.Errorf("at least one grant type is required")
	}
	if !grantTypesAreAllowed(s.GrantTypes) {
		return fmt.Errorf("invalid grant type - %v - allowed grant types are %v", s.GrantTypes, AllowedGrantTypes)
	}

	// Validate the endpoints.
	if err := s.AuthorizationEndpoint.Validate(); err != nil {
		return errors.Wrapf(err, "authorization endpoint validation failed")
	}
	if err := s.IntrospectionEndpoint.Validate(); err != nil {
		return errors.Wrapf(err, "introspection endpoint validation failed")
	}
	if err := s.TokenEndpoint.Validate(); err != nil {
		return errors.Wrapf(err, "token endpoint validation failed")
	}
	if err := s.UserInfoEndpoint.Validate(); err != nil {
		return errors.Wrapf(err, "userinfo endpoint validation failed")
	}
	if err := s.JWKSEndpoint.Validate(); err != nil {
		return errors.Wrapf(err, "JWKS endpoint validation failed")
	}
	if err := s.WellKnownEndpoint.Validate(); err != nil {
		return errors.Wrapf(err, "well-known endpoint validation failed")
	}
	if err := s.LoginEndpoint.Validate(); err != nil {
		return errors.Wrapf(err, "login endpoint validation failed")
	}
	if err := s.Connection.Validate(); err != nil {
		return errors.Wrapf(err, "connection validation failed")
	}

	if err := validateKeys(s.Keys); err != nil {
		return errors.Wrapf(err, "invalid keys configuration")
	}

	return nil
}

func validateKeys(keys []crypto.PrivateKey) error {
	if len(keys) == 0 {
		return fmt.Errorf("at least one key is required")
	}
	for _, k := range keys {
		if k == nil {
			return fmt.Errorf("key cannot be nil")
		}
		_, ok := k.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("only RSA keys are supported")
		}
	}
	return nil
}
