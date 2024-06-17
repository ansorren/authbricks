package config

import "fmt"

type IntrospectionEndpoint struct {
	// Endpoint is the URL of the introspection endpoint.
	Endpoint string
}

// Validate validates the introspection endpoint configuration.
func (i IntrospectionEndpoint) Validate() error {
	if i.Endpoint == "" {
		return fmt.Errorf("introspection endpoint URL is required")
	}
	return nil
}
