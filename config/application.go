package config

import (
	"fmt"
)

const (
	// ResponseTypeCode is the code response type.
	// See https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
	ResponseTypeCode = "code"
	// ResponseTypeIDToken is the id_token response type.
	// See https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#id_token
	ResponseTypeIDToken = "id_token"
	// ResponseTypeNone is the none response type.
	// See https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none
	ResponseTypeNone = "none"
	// ResponseTypeCodeIDToken is the code id_token response type.
	// See https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Combinations
	ResponseTypeCodeIDToken = "code id_token"
)

var (
	AllowedResponseTypes = []string{ResponseTypeCode, ResponseTypeIDToken, ResponseTypeNone, ResponseTypeCodeIDToken}
)

// Application is used to configure an application.
type Application struct {
	// Name is the name of the application.
	Name string
	// RedirectURIs is the list of allowed redirect URIs.
	RedirectURIs []string
	// ResponseTypes is the list of allowed response types.
	ResponseTypes []string
	// GrantTypes is the list of allowed grant types.
	GrantTypes []string
	// PKCERequired is true if the authorization endpoint requires PKCE, even for confidential clients.
	// Public clients are always required to use PKCE.
	PKCERequired bool
	// When S256CodeChallengeMethodRequired is true, the authorization endpoint requires the use of the S256 code challenge method.
	// This effectively disables the `plain` code challenge method.
	S256CodeChallengeMethodRequired bool
	// AllowedAuthenticationMethods is the list of allowed authentication methods.
	AllowedAuthenticationMethods []string
	// Scopes is the list of scopes that the application is allowed to request.
	// By default, if empty, the application is not allowed to request any scopes.
	Scopes []string
}

func responseTypesAreAllowed(responseTypes []string) bool {
	for _, rt := range responseTypes {
		if !contains(AllowedResponseTypes, rt) {
			return false
		}
	}
	return true
}

// Validate validates the application configuration.
func (a Application) Validate() error {
	if a.Name == "" {
		return fmt.Errorf("application Name is required")
	}
	if err := validateRedirectURIs(a.RedirectURIs); err != nil {
		return err
	}

	if len(a.ResponseTypes) == 0 {
		return fmt.Errorf("at least one response type is required")
	}
	if !responseTypesAreAllowed(a.ResponseTypes) {
		return fmt.Errorf("invalid response type")
	}

	if len(a.GrantTypes) == 0 {
		return fmt.Errorf("at least one grant type is required")
	}
	if !grantTypesAreAllowed(a.GrantTypes) {
		return fmt.Errorf("invalid grant type")
	}
	return nil
}

func validateRedirectURIs(redirectURIs []string) error {
	if len(redirectURIs) == 0 {
		return fmt.Errorf("at least one redirect URI is required")
	}
	for _, uri := range redirectURIs {
		if uri == "" {
			return fmt.Errorf("empty redirect URI")
		}
	}
	return nil
}
