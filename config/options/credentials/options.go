package credentials

import "go.authbricks.com/bricks/config"

type Option func(*config.Credentials)

// New creates a new configuration with default values.
func New(opts ...Option) config.Credentials {
	creds := config.Credentials{}
	for _, opt := range opts {
		opt(&creds)
	}
	return creds
}

// WithApplication sets the Application.
func WithApplication(application string) Option {
	return func(c *config.Credentials) {
		c.Application = application
	}
}

// WithClientID sets the client ID.
func WithClientID(clientID string) Option {
	return func(c *config.Credentials) {
		c.ClientID = clientID
	}
}

// WithClientSecret sets the client secret.
func WithClientSecret(clientSecret string) Option {
	return func(c *config.Credentials) {
		c.ClientSecret = clientSecret
	}
}
