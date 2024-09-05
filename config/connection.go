package config

import (
	"fmt"

	"github.com/pkg/errors"
)

// EmailPasswordConnection is used to configure the email/password connection.
type EmailPasswordConnection struct {
	Enabled bool
}

// Validate validates the email/password connection.
func (e *EmailPasswordConnection) Validate() error {
	return nil
}

// OIDCConnection is used to configure the OIDC connection.
type OIDCConnection struct {
	Name              string
	Enabled           bool
	ClientID          string
	ClientSecret      string
	Scopes            []string
	RedirectURI       string
	WellKnownEndpoint string
}

// Validate validates the OIDC connection.
func (o OIDCConnection) Validate() error {
	// If the connection is not enabled, we don't need to validate it.
	if !o.Enabled {
		return nil
	}
	if o.Name == "" {
		return fmt.Errorf("name is required")
	}

	if o.ClientID == "" {
		return fmt.Errorf("client ID is required")
	}
	if o.ClientSecret == "" {
		return fmt.Errorf("client secret is required")
	}
	if len(o.Scopes) == 0 {
		return fmt.Errorf("at least one scope is required")
	}
	if o.RedirectURI == "" {
		return fmt.Errorf("redirect URI is required")
	}
	if o.WellKnownEndpoint == "" {
		return fmt.Errorf("well known endpoint is required")
	}
	return nil
}

// Connection is used to configure the connections available on the service.
type Connection struct {
	EmailPassword *EmailPasswordConnection
	OIDC          []OIDCConnection
}

// notUniqueOIDCConnectionNames returns true if the OIDC connection names are not unique.
func notUniqueOIDCConnectionNames(oidc []OIDCConnection) bool {
	names := make(map[string]struct{})
	for _, o := range oidc {
		if _, ok := names[o.Name]; ok {
			return true
		}
		names[o.Name] = struct{}{}
	}
	return false
}

func (c Connection) Validate() error {
	if err := c.EmailPassword.Validate(); err != nil {
		return errors.Wrapf(err, "email/password connection validation failed")
	}

	for _, oidc := range c.OIDC {
		if err := oidc.Validate(); err != nil {
			return errors.Wrapf(err, "OIDC connection validation failed")
		}
	}

	if notUniqueOIDCConnectionNames(c.OIDC) {
		return fmt.Errorf("OIDC connection names must be unique")
	}

	return nil
}
