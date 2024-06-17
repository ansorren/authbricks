package config

import "fmt"

type RevocationEndpoint struct {
	// Endpoint is the URL of the revocation endpoint.
	Endpoint string
}

// Validate validates the revocation endpoint configuration.
func (r RevocationEndpoint) Validate() error {
	if r.Endpoint == "" {
		return fmt.Errorf("revocation endpoint URL is required")
	}
	return nil
}
