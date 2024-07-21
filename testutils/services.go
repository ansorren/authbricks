package testutils

import (
	"crypto"
	"testing"

	"go.authbricks.com/bricks/config"
	abcrypto "go.authbricks.com/bricks/crypto"

	"github.com/stretchr/testify/require"
)

// privateKey generates a new RSA private key for testing.
func privateKey(t *testing.T) crypto.PrivateKey {
	key, err := abcrypto.GenerateRSAPrivateKey()
	require.Nil(t, err)
	return key
}

// TestService generates a new service for testing.
func TestService(t *testing.T) config.Service {
	t.Helper()
	key := privateKey(t)
	return config.Service{
		Name:        "test-service",
		Identifier:  "test-identifier",
		Description: "test-description",
		ServiceMetadata: map[string]string{
			"key": "value",
		},
		AllowedClientMetadata: []string{"key"},
		Scopes:                []string{"calendar:read"},
		GrantTypes:            []string{config.GrantTypeAuthorizationCode, config.GrantTypeClientCredentials},
		ResponseTypes:         []string{config.ResponseTypeCode},
		AuthorizationEndpoint: config.AuthorizationEndpoint{
			Endpoint:                        "/oauth2/authorize",
			PKCERequired:                    true,
			S256CodeChallengeMethodRequired: true,
		},
		IntrospectionEndpoint: config.IntrospectionEndpoint{
			Endpoint: "/oauth2/introspect",
		},
		TokenEndpoint: config.TokenEndpoint{
			Endpoint:                     "/oauth2/token",
			AllowedAuthenticationMethods: []string{config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost},
		},
		UserInfoEndpoint: config.UserInfoEndpoint{
			Endpoint: "/oauth2/userinfo",
		},
		JWKSEndpoint: config.JWKSEndpoint{
			Endpoint: "/oauth2/jwks",
		},
		WellKnownEndpoint: config.WellKnownEndpoint{
			Endpoint: "/oauth2/.well-known/openid-configuration",
		},
		Keys: []crypto.PrivateKey{key},
	}
}

// TestApplication generates a new application for testing that can call the given service.
func TestApplication(_ *testing.T, service config.Service) config.Application {
	return config.Application{
		Name:          "test-application",
		Description:   "test-description",
		Service:       service.Name,
		Public:        false,
		RedirectURIs:  []string{"https://example.com/oauth2/callback"},
		ResponseTypes: []string{config.ResponseTypeCode},
		GrantTypes:    []string{config.GrantTypeAuthorizationCode},
		Scopes:        []string{"calendar:read"},
		PKCERequired:  true,
	}
}
