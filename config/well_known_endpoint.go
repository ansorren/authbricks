package config

import "fmt"

// WellKnownEndpoint is used to configure the well-known endpoint.
type WellKnownEndpoint struct {
	// Endpoint is the URL of the well-known endpoint.
	Endpoint string
}

// Validate validates the well-known endpoint configuration.
func (w WellKnownEndpoint) Validate() error {
	if w.Endpoint == "" {
		return fmt.Errorf("well-known endpoint URL is required")
	}
	return nil
}
