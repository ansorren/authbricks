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
	// AllowedResponseTypes is the list of allowed response types.
	AllowedResponseTypes = []string{ResponseTypeCode, ResponseTypeIDToken, ResponseTypeNone, ResponseTypeCodeIDToken}
)

// Application is used to configure an application.
type Application struct {
	// Name is the name of the application.
	Name string
	// Service is the name of the service that the application belongs to.
	Service string
	// Description is the description of the application.
	Description string
	// Public is true if the application is a public client, like in the case of a single page application
	// or a CLI tool.
	Public bool
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

func onlyClientCredentialsAllowed(grantTypes []string) bool {
	return len(grantTypes) == 1 && grantTypes[0] == GrantTypeClientCredentials
}

// validateResponseTypes checks if the given response types are allowed.
func validateResponseTypes(responseTypes []string, grantTypes []string) error {
	if len(responseTypes) == 0 && !onlyClientCredentialsAllowed(grantTypes) {
		return fmt.Errorf("empty response types")
	}
	if len(responseTypes) == 0 && onlyClientCredentialsAllowed(grantTypes) {
		return nil
	}

	for _, rt := range responseTypes {
		if !contains(AllowedResponseTypes, rt) {
			return fmt.Errorf("invalid response type: %s", rt)
		}
	}
	return nil
}

// Validate validates the application configuration.
func (a Application) Validate() error {
	if a.Name == "" {
		return fmt.Errorf("application Name is required")
	}

	if a.Service == "" {
		return fmt.Errorf("service Name is required")
	}

	if a.Public && !a.PKCERequired {
		return fmt.Errorf("public applications are required to use PKCE")
	}

	if err := validateRedirectURIs(a.RedirectURIs); err != nil {
		return err
	}

	if err := validateResponseTypes(a.ResponseTypes, a.GrantTypes); err != nil {
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

// validateRedirectURIs validates the redirect URIs.
func validateRedirectURIs(redirectURIs []string) error {
	// we consider an empty list of redirect URIs as valid
	// as some clients might not have any redirect URIs.
	// On the other hand, an empty URI is invalid.
	if len(redirectURIs) == 0 {
		return nil
	}
	for _, uri := range redirectURIs {
		if uri == "" {
			return fmt.Errorf("empty redirect URI")
		}
	}
	return nil
}
