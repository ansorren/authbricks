package config

import "fmt"

// Credentials is used to configure credentials used to authenticate an application.
type Credentials struct {
	Application  string
	ClientID     string
	ClientSecret string
}

func (c Credentials) Validate(isPublic bool) error {
	if c.Application == "" {
		return fmt.Errorf("application name is required")
	}
	if c.ClientID == "" {
		return fmt.Errorf("client ID is required")
	}

	if !isPublic && c.ClientSecret == "" {
		return fmt.Errorf("client secret is required for non-public applications")
	}

	return nil
}
