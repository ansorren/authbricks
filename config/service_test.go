package config

import (
	"crypto"
	"testing"
	"time"

	abcrypto "go.authbricks.com/bricks/crypto"

	"github.com/stretchr/testify/require"
)

func TestServiceValidate(t *testing.T) {
	key, err := abcrypto.GenerateRSAPrivateKey()
	require.Nil(t, err)

	tests := []struct {
		Name          string
		Service       Service
		ExpectedError bool
	}{
		{
			Name:          "empty Service",
			Service:       Service{},
			ExpectedError: true,
		},
		{
			Name:          "missing Service Name",
			Service:       Service{Identifier: "test"},
			ExpectedError: true,
		},
		{
			Name:          "missing Service identifier",
			Service:       Service{Name: "test"},
			ExpectedError: true,
		},
		{
			Name:          "missing Service Scopes",
			Service:       Service{Name: "test", Identifier: "test"},
			ExpectedError: true,
		},
		{
			Name: "at least one grant type is required",
			Service: Service{
				Name:       "test",
				Identifier: "test",
				Scopes:     []string{"test"},
			},
			ExpectedError: true,
		},
		{
			Name: "invalid grant type",
			Service: Service{
				Name:       "test",
				Identifier: "test",
				Scopes:     []string{"test"},
				GrantTypes: []string{"invalid"},
			},
			ExpectedError: true,
		},
		{
			Name: "empty authorization endpoint URL",
			Service: Service{
				Name:       "test",
				Identifier: "test",
				Scopes:     []string{"test"},
				GrantTypes: []string{GrantTypeAuthorizationCode},
				AuthorizationEndpoint: AuthorizationEndpoint{
					Endpoint: "",
				},
			},
			ExpectedError: true,
		},
		{
			Name: "invalid PKCE configuration",
			Service: Service{
				Name:       "test",
				Identifier: "test",
				Scopes:     []string{"test"},
				GrantTypes: []string{GrantTypeAuthorizationCode},
				AuthorizationEndpoint: AuthorizationEndpoint{
					Endpoint:                        "http://localhost:8080/oauth2/authorize",
					PKCERequired:                    false,
					S256CodeChallengeMethodRequired: true,
				},
			},
			ExpectedError: true,
		},
		{
			Name: "empty introspection endpoint URL",
			Service: Service{
				Name:       "test",
				Identifier: "test",
				Scopes:     []string{"test"},
				GrantTypes: []string{GrantTypeAuthorizationCode},
				ServiceMetadata: ServiceMetadata{
					"foo": "bar",
				},
				AuthorizationEndpoint: AuthorizationEndpoint{
					Endpoint: "http://localhost:8080/oauth2/authorize",
				},
				IntrospectionEndpoint: IntrospectionEndpoint{
					Endpoint: "",
				},
				TokenEndpoint: TokenEndpoint{
					Endpoint:                     "http://localhost:8080/oauth2/token",
					AllowedAuthenticationMethods: []string{AuthenticationMethodClientSecretBasic},
				},
			},
			ExpectedError: true,
		},
		{
			Name: "empty token endpoint URL",
			Service: Service{
				Name:       "test",
				Identifier: "test",
				Scopes:     []string{"test"},
				GrantTypes: []string{GrantTypeAuthorizationCode},
				ServiceMetadata: ServiceMetadata{
					"foo": "bar",
				},
				AuthorizationEndpoint: AuthorizationEndpoint{
					Endpoint: "http://localhost:8080/oauth2/authorize",
				},
				IntrospectionEndpoint: IntrospectionEndpoint{
					Endpoint: "http://localhost:8080/oauth2/introspect",
				},
				TokenEndpoint: TokenEndpoint{
					Endpoint:                     "",
					AllowedAuthenticationMethods: []string{AuthenticationMethodClientSecretBasic},
				},
			},
			ExpectedError: true,
		},
		{
			Name: "empty authentication method for token endpoint",
			Service: Service{
				Name:       "test",
				Identifier: "test",
				Scopes:     []string{"test"},
				GrantTypes: []string{GrantTypeAuthorizationCode},
				ServiceMetadata: ServiceMetadata{
					"foo": "bar",
				},
				AuthorizationEndpoint: AuthorizationEndpoint{
					Endpoint: "http://localhost:8080/oauth2/authorize",
				},
				IntrospectionEndpoint: IntrospectionEndpoint{
					Endpoint: "http://localhost:8080/oauth2/introspect",
				},
				TokenEndpoint: TokenEndpoint{
					Endpoint:                     "http://localhost:8080/oauth2/token",
					AllowedAuthenticationMethods: []string{""},
				},
			},
			ExpectedError: true,
		},
		{
			Name: "invalid authentication method for token endpoint",
			Service: Service{
				Name:       "test",
				Identifier: "test",
				Scopes:     []string{"test"},
				GrantTypes: []string{GrantTypeAuthorizationCode},
				ServiceMetadata: ServiceMetadata{
					"foo": "bar",
				},
				AuthorizationEndpoint: AuthorizationEndpoint{
					Endpoint: "http://localhost:8080/oauth2/authorize",
				},
				IntrospectionEndpoint: IntrospectionEndpoint{
					Endpoint: "http://localhost:8080/oauth2/introspect",
				},
				TokenEndpoint: TokenEndpoint{
					Endpoint:                     "http://localhost:8080/oauth2/token",
					AllowedAuthenticationMethods: []string{"invalid"},
				},
			},
			ExpectedError: true,
		},
		{
			Name: "empty userinfo endpoint",
			Service: Service{
				Name:       "test",
				Identifier: "test",
				Scopes:     []string{"test"},
				GrantTypes: []string{GrantTypeAuthorizationCode},
				ServiceMetadata: ServiceMetadata{
					"foo": "bar",
				},
				AuthorizationEndpoint: AuthorizationEndpoint{
					Endpoint: "http://localhost:8080/oauth2/authorize",
				},
				IntrospectionEndpoint: IntrospectionEndpoint{
					Endpoint: "http://localhost:8080/oauth2/introspect",
				},
				TokenEndpoint: TokenEndpoint{
					Endpoint:                     "http://localhost:8080/oauth2/token",
					AllowedAuthenticationMethods: []string{"invalid"},
				},
				UserInfoEndpoint: UserInfoEndpoint{
					Endpoint: "",
				},
			},
			ExpectedError: true,
		},
		{
			Name: "empty jwks endpoint",
			Service: Service{
				Name:       "test",
				Identifier: "test",
				Scopes:     []string{"test"},
				GrantTypes: []string{GrantTypeAuthorizationCode},
				ServiceMetadata: ServiceMetadata{
					"foo": "bar",
				},
				AuthorizationEndpoint: AuthorizationEndpoint{
					Endpoint: "http://localhost:8080/oauth2/authorize",
				},
				IntrospectionEndpoint: IntrospectionEndpoint{
					Endpoint: "http://localhost:8080/oauth2/introspect",
				},
				TokenEndpoint: TokenEndpoint{
					Endpoint:                     "http://localhost:8080/oauth2/token",
					AllowedAuthenticationMethods: []string{AuthenticationMethodClientSecretBasic},
				},
				UserInfoEndpoint: UserInfoEndpoint{
					Endpoint: "http://localhost:8080/oauth2/userinfo",
				},
				Keys: []crypto.PrivateKey{key},
			},
			ExpectedError: true,
		},
		{
			Name: "empty well-known endpoint",
			Service: Service{
				Name:       "test",
				Identifier: "test",
				Scopes:     []string{"test"},
				GrantTypes: []string{GrantTypeAuthorizationCode},
				ServiceMetadata: ServiceMetadata{
					"foo": "bar",
				},
				AuthorizationEndpoint: AuthorizationEndpoint{
					Endpoint: "http://localhost:8080/oauth2/authorize",
				},
				IntrospectionEndpoint: IntrospectionEndpoint{
					Endpoint: "http://localhost:8080/oauth2/introspect",
				},
				TokenEndpoint: TokenEndpoint{
					Endpoint:                     "http://localhost:8080/oauth2/token",
					AllowedAuthenticationMethods: []string{AuthenticationMethodClientSecretBasic},
				},
				UserInfoEndpoint: UserInfoEndpoint{
					Endpoint: "http://localhost:8080/oauth2/userinfo",
				},
				JWKSEndpoint: JWKSEndpoint{
					Endpoint: "http://localhost:8080/oauth2/jwks",
				},
				Keys: []crypto.PrivateKey{key},
			},
			ExpectedError: true,
		},
		{
			Name: "empty login endpoint",
			Service: Service{
				Name:       "test",
				Identifier: "test",
				Scopes:     []string{"test"},
				GrantTypes: []string{GrantTypeAuthorizationCode},
				ServiceMetadata: ServiceMetadata{
					"foo": "bar",
				},
				AuthorizationEndpoint: AuthorizationEndpoint{
					Endpoint: "http://localhost:8080/oauth2/authorize",
				},
				IntrospectionEndpoint: IntrospectionEndpoint{
					Endpoint: "http://localhost:8080/oauth2/introspect",
				},
				TokenEndpoint: TokenEndpoint{
					Endpoint:                     "http://localhost:8080/oauth2/token",
					AllowedAuthenticationMethods: []string{AuthenticationMethodClientSecretBasic},
				},
				UserInfoEndpoint: UserInfoEndpoint{
					Endpoint: "http://localhost:8080/oauth2/userinfo",
				},
				JWKSEndpoint: JWKSEndpoint{
					Endpoint: "http://localhost:8080/oauth2/jwks",
				},
				WellKnownEndpoint: WellKnownEndpoint{
					Endpoint: "http://localhost:8080/oauth2/.well-known",
				},
				Keys: []crypto.PrivateKey{key},
			},
			ExpectedError: true,
		},
		{
			Name: "no session timeout for login endpoint",
			Service: Service{
				Name:       "test",
				Identifier: "test",
				Scopes:     []string{"test"},
				GrantTypes: []string{GrantTypeAuthorizationCode},
				ServiceMetadata: ServiceMetadata{
					"foo": "bar",
				},
				AuthorizationEndpoint: AuthorizationEndpoint{
					Endpoint: "http://localhost:8080/oauth2/authorize",
				},
				IntrospectionEndpoint: IntrospectionEndpoint{
					Endpoint: "http://localhost:8080/oauth2/introspect",
				},
				TokenEndpoint: TokenEndpoint{
					Endpoint:                     "http://localhost:8080/oauth2/token",
					AllowedAuthenticationMethods: []string{AuthenticationMethodClientSecretBasic},
				},
				UserInfoEndpoint: UserInfoEndpoint{
					Endpoint: "http://localhost:8080/oauth2/userinfo",
				},
				JWKSEndpoint: JWKSEndpoint{
					Endpoint: "http://localhost:8080/oauth2/jwks",
				},
				WellKnownEndpoint: WellKnownEndpoint{
					Endpoint: "http://localhost:8080/oauth2/.well-known",
				},
				LoginEndpoint: LoginEndpoint{
					Endpoint: "/login",
				},
				Keys: []crypto.PrivateKey{key},
			},
			ExpectedError: true,
		},
		{
			Name: "OIDC connection enabled without OIDC config",
			Service: Service{
				Name:       "test",
				Identifier: "test",
				Scopes:     []string{"test"},
				GrantTypes: []string{GrantTypeAuthorizationCode},
				ServiceMetadata: ServiceMetadata{
					"foo": "bar",
				},
				AuthorizationEndpoint: AuthorizationEndpoint{
					Endpoint: "http://localhost:8080/oauth2/authorize",
				},
				IntrospectionEndpoint: IntrospectionEndpoint{
					Endpoint: "http://localhost:8080/oauth2/introspect",
				},
				TokenEndpoint: TokenEndpoint{
					Endpoint:                     "http://localhost:8080/oauth2/token",
					AllowedAuthenticationMethods: []string{AuthenticationMethodClientSecretBasic},
				},
				UserInfoEndpoint: UserInfoEndpoint{
					Endpoint: "http://localhost:8080/oauth2/userinfo",
				},
				JWKSEndpoint: JWKSEndpoint{
					Endpoint: "http://localhost:8080/oauth2/jwks",
				},
				WellKnownEndpoint: WellKnownEndpoint{
					Endpoint: "http://localhost:8080/oauth2/.well-known",
				},
				LoginEndpoint: LoginEndpoint{
					Endpoint:       "/login",
					SessionTimeout: 30 * time.Minute,
				},
				Connection: Connection{
					EmailPassword: &EmailPasswordConnection{
						Enabled: true,
					},
					OIDC: []OIDCConnection{
						{
							Enabled: true,
						},
					},
				},
				Keys: []crypto.PrivateKey{key},
			},
			ExpectedError: true,
		},
		{
			Name: "no keys",
			Service: Service{
				Name:       "test",
				Identifier: "test",
				Scopes:     []string{"test"},
				GrantTypes: []string{GrantTypeAuthorizationCode},
				ServiceMetadata: ServiceMetadata{
					"foo": "bar",
				},
				AuthorizationEndpoint: AuthorizationEndpoint{
					Endpoint: "http://localhost:8080/oauth2/authorize",
				},
				IntrospectionEndpoint: IntrospectionEndpoint{
					Endpoint: "http://localhost:8080/oauth2/introspect",
				},
				TokenEndpoint: TokenEndpoint{
					Endpoint:                     "http://localhost:8080/oauth2/token",
					AllowedAuthenticationMethods: []string{AuthenticationMethodClientSecretBasic},
				},
				UserInfoEndpoint: UserInfoEndpoint{
					Endpoint: "http://localhost:8080/oauth2/userinfo",
				},
				JWKSEndpoint: JWKSEndpoint{
					Endpoint: "http://localhost:8080/oauth2/jwks",
				},
				WellKnownEndpoint: WellKnownEndpoint{
					Endpoint: "http://localhost:8080/oauth2/.well-known",
				},
				LoginEndpoint: LoginEndpoint{
					Endpoint:       "/login",
					SessionTimeout: 30 * time.Minute,
				},
				Keys: []crypto.PrivateKey{},
			},
			ExpectedError: true,
		},
		{
			Name: "valid Service",
			Service: Service{
				Name:       "test",
				Identifier: "test",
				Scopes:     []string{"test"},
				GrantTypes: []string{GrantTypeAuthorizationCode},
				ServiceMetadata: ServiceMetadata{
					"foo": "bar",
				},
				AuthorizationEndpoint: AuthorizationEndpoint{
					Endpoint: "http://localhost:8080/oauth2/authorize",
				},
				IntrospectionEndpoint: IntrospectionEndpoint{
					Endpoint: "http://localhost:8080/oauth2/introspect",
				},
				TokenEndpoint: TokenEndpoint{
					Endpoint:                     "http://localhost:8080/oauth2/token",
					AllowedAuthenticationMethods: []string{AuthenticationMethodClientSecretBasic},
				},
				UserInfoEndpoint: UserInfoEndpoint{
					Endpoint: "http://localhost:8080/oauth2/userinfo",
				},
				JWKSEndpoint: JWKSEndpoint{
					Endpoint: "http://localhost:8080/oauth2/jwks",
				},
				WellKnownEndpoint: WellKnownEndpoint{
					Endpoint: "http://localhost:8080/oauth2/.well-known",
				},
				LoginEndpoint: LoginEndpoint{
					Endpoint:       "/login",
					SessionTimeout: 30 * time.Minute,
				},
				Keys: []crypto.PrivateKey{key},
			},
			ExpectedError: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			tt := tt
			if err := tt.Service.Validate(); (err != nil) != tt.ExpectedError {
				t.Errorf("Service.Validate() error = %v, ExpectedError %v", err, tt.ExpectedError)
			}
		})
	}
}
