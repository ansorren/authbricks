package config

import "fmt"

const (
	AuthenticationMethodClientSecretBasic = "client_secret_basic"
	AuthenticationMethodClientSecretPost  = "client_secret_post"
)

var AllowedAuthenticationMethods = []string{AuthenticationMethodClientSecretBasic, AuthenticationMethodClientSecretPost}

// TokenEndpoint is used to configure the token endpoint.
type TokenEndpoint struct {
	// Endpoint is the URL of the token endpoint.
	Endpoint string
	// AllowedAuthenticationMethods is the list of allowed authentication methods.
	AllowedAuthenticationMethods []string
}

func allowedAuthenticationMethods(authMethods []string) bool {
	for _, am := range authMethods {
		if !contains(AllowedAuthenticationMethods, am) {
			return false
		}
	}
	return true
}

func (t TokenEndpoint) Validate() error {
	if t.Endpoint == "" {
		return fmt.Errorf("token endpoint URL is required")
	}
	if len(t.AllowedAuthenticationMethods) == 0 {
		return fmt.Errorf("at least one allowed authentication method is required")
	}
	if !allowedAuthenticationMethods(t.AllowedAuthenticationMethods) {
		return fmt.Errorf("invalid authentication method - %v - allowed authentication methods are %v", t.AllowedAuthenticationMethods, AllowedAuthenticationMethods)
	}
	return nil
}
