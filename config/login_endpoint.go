package config

import (
	"fmt"
	"time"
)

type LoginEndpoint struct {
	// Endpoint is the path of the login endpoint.
	Endpoint string
	// SessionTimeout is the timeout for the login session.
	SessionTimeout time.Duration
}

// Validate validates the login endpoint configuration.
func (l LoginEndpoint) Validate() error {
	if l.Endpoint == "" {
		return fmt.Errorf("login endpoint path is required")
	}
	if l.SessionTimeout == 0 {
		return fmt.Errorf("login session timeout is required")
	}
	return nil
}
