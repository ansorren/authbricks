package config

import "fmt"

// UserInfoEndpoint is used to configure the user info endpoint.
type UserInfoEndpoint struct {
	// Endpoint is the URL of the user info endpoint.
	Endpoint string
}

// Validate validates the user info endpoint configuration.
func (u UserInfoEndpoint) Validate() error {
	if u.Endpoint == "" {
		return fmt.Errorf("user info endpoint URL is required")
	}
	return nil
}
