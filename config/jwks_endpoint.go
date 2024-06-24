package config

import "fmt"

// JWKSEndpoint is the JSON Web Key Set endpoint configuration.
type JWKSEndpoint struct {
	// Endpoint is the URL of the revocation endpoint.
	Endpoint string
}

// Validate validates the revocation endpoint configuration.
func (j JWKSEndpoint) Validate() error {
	if j.Endpoint == "" {
		return fmt.Errorf("JWKS endpoint URL is required")
	}
	return nil
}
