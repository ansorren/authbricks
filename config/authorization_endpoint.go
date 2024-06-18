package config

import "fmt"

// AuthorizationEndpoint is used to configure the authorization endpoint.
type AuthorizationEndpoint struct {
	// Endpoint is the URL of the authorization endpoint.
	Endpoint string
	// PKCERequired is true if the authorization endpoint requires PKCE, even for confidential clients.
	// Public clients are always required to use PKCE.
	PKCERequired bool
	// When S256CodeChallengeMethodRequired is true, the authorization endpoint requires the use of the S256 code challenge method.
	// This effectively disables the `plain` code challenge method.
	S256CodeChallengeMethodRequired bool
}

// Validate validates the authorization endpoint configuration.
func (a AuthorizationEndpoint) Validate() error {
	if a.Endpoint == "" {
		return fmt.Errorf("authorization endpoint URL is required")
	}

	if !a.PKCERequired && a.S256CodeChallengeMethodRequired {
		return fmt.Errorf("code challenge method S256 can only be required when PKCE is required")
	}
	return nil
}
