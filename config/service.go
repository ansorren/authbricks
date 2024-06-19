package config

import (
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

// allowedGrantTypes checks if the given grant types are allowed.
func allowedGrantTypes(grantTypes []string) bool {
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
		return fmt.Errorf("service Name is required")
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
	if !allowedGrantTypes(s.GrantTypes) {
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

	return nil
}