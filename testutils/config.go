package testutils

import (
	"crypto"
	"fmt"
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

// TestConfig is used to generate a new configuration for testing.
type TestConfig struct {
	Services     []config.Service
	Applications []config.Application
	Credentials  []config.Credentials
}

// NewTestConfig returns a ready-to-use TestConfig.
func NewTestConfig(t *testing.T, addr string) TestConfig {
	t.Helper()
	firstKey := privateKey(t)
	secondKey := privateKey(t)

	firstService := config.Service{
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
		Keys: []crypto.PrivateKey{firstKey, secondKey},
	}

	testApp := config.Application{
		Name:                         "test-application",
		Description:                  "test-description",
		Service:                      firstService.Name,
		Public:                       false,
		AllowedAuthenticationMethods: []string{config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost},
		RedirectURIs:                 []string{"https://example.com/oauth2/callback"},
		ResponseTypes:                []string{config.ResponseTypeCode},
		GrantTypes:                   []string{config.GrantTypeAuthorizationCode, config.GrantTypeRefreshToken},
		Scopes:                       []string{"calendar:read"},
		PKCERequired:                 true,
	}

	firstCredentials := config.Credentials{
		Application:  testApp.Name,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}

	customersKey := privateKey(t)
	customersService := config.Service{
		Name:          "customers",
		Identifier:    fmt.Sprintf("https://%s/customers", addr),
		Scopes:        []string{"openid", "profile", "email", "offline_access", "customers:read"},
		GrantTypes:    []string{config.GrantTypeAuthorizationCode, config.GrantTypeRefreshToken, config.GrantTypeClientCredentials},
		ResponseTypes: []string{config.ResponseTypeCode, config.ResponseTypeIDToken, config.ResponseTypeIDToken},
		AuthorizationEndpoint: config.AuthorizationEndpoint{
			Endpoint: "customers/oauth2/authorize",
		},
		IntrospectionEndpoint: config.IntrospectionEndpoint{
			Endpoint: "customers/oauth2/introspect",
		},
		TokenEndpoint: config.TokenEndpoint{
			Endpoint:                     "customers/oauth2/token",
			AllowedAuthenticationMethods: []string{config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost},
		},
		UserInfoEndpoint: config.UserInfoEndpoint{
			Endpoint: "customers/oauth2/userinfo",
		},
		JWKSEndpoint: config.JWKSEndpoint{
			Endpoint: "customers/oauth2/jwks",
		},
		WellKnownEndpoint: config.WellKnownEndpoint{
			Endpoint: "customers/oauth2/.well-known/openid-configuration",
		},
		Keys: []crypto.PrivateKey{customersKey},
	}

	loginApplication := config.Application{
		Name:                            "login-application",
		Description:                     "Login Application",
		Service:                         customersService.Name,
		Public:                          false,
		RedirectURIs:                    []string{"http://localhost:8080/callback"},
		ResponseTypes:                   []string{config.ResponseTypeCode},
		GrantTypes:                      []string{config.GrantTypeAuthorizationCode, config.GrantTypeRefreshToken},
		Scopes:                          []string{"openid", "profile", "offline_access"},
		PKCERequired:                    false,
		S256CodeChallengeMethodRequired: false,
		AllowedAuthenticationMethods:    []string{config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost},
	}

	loginApplicationCredentials := config.Credentials{
		Application:  loginApplication.Name,
		ClientID:     "login-client-id",
		ClientSecret: "login-client-secret",
	}

	publicApplication := config.Application{
		Name:                            "public-client",
		Description:                     "Public Client",
		Public:                          true,
		Service:                         customersService.Name,
		RedirectURIs:                    []string{"http://localhost:8080/callback"},
		ResponseTypes:                   []string{config.ResponseTypeCode},
		GrantTypes:                      []string{config.GrantTypeAuthorizationCode},
		Scopes:                          []string{"openid", "profile", "offline_access"},
		PKCERequired:                    true,
		S256CodeChallengeMethodRequired: false,
		AllowedAuthenticationMethods:    []string{config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost},
	}

	publicCredentials := config.Credentials{
		Application:  publicApplication.Name,
		ClientID:     "publicApplication-client-id",
		ClientSecret: "",
	}

	s256RequiredApplication := config.Application{
		Name:                            "s256-required",
		Description:                     "S256 Required",
		Public:                          true,
		Service:                         customersService.Name,
		RedirectURIs:                    []string{"http://localhost:8080/callback"},
		ResponseTypes:                   []string{config.ResponseTypeCode},
		GrantTypes:                      []string{config.GrantTypeAuthorizationCode},
		Scopes:                          []string{"openid", "profile", "offline_access"},
		PKCERequired:                    true,
		S256CodeChallengeMethodRequired: true,
		AllowedAuthenticationMethods:    []string{config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost},
	}

	s256RequiredCredentials := config.Credentials{
		Application:  s256RequiredApplication.Name,
		ClientID:     "s256-required-client-id",
		ClientSecret: "",
	}

	helpdeskApplication := config.Application{
		Name:                            "helpdesk-application",
		Description:                     "Helpdesk Application",
		Service:                         customersService.Name,
		Public:                          false,
		GrantTypes:                      []string{config.GrantTypeClientCredentials},
		ResponseTypes:                   []string{config.ResponseTypeCode},
		Scopes:                          []string{"customers:read"},
		PKCERequired:                    false,
		S256CodeChallengeMethodRequired: false,
		AllowedAuthenticationMethods:    []string{config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost},
	}

	helpdeskCredentials := config.Credentials{
		Application:  helpdeskApplication.Name,
		ClientID:     "helpdesk-client-id",
		ClientSecret: "helpdesk-client-secret",
	}

	employeesKey := privateKey(t)
	employeesService := config.Service{
		Name:          "employees",
		Identifier:    fmt.Sprintf("https://%s/employees", addr),
		Scopes:        []string{"openid", "profile", "email", "offline_access"},
		GrantTypes:    []string{config.GrantTypeAuthorizationCode, config.GrantTypeRefreshToken, config.GrantTypeClientCredentials},
		ResponseTypes: []string{config.ResponseTypeCode, config.ResponseTypeIDToken, config.ResponseTypeIDToken},
		AuthorizationEndpoint: config.AuthorizationEndpoint{
			Endpoint: "employees/oauth2/authorize",
		},
		IntrospectionEndpoint: config.IntrospectionEndpoint{
			Endpoint: "employees/oauth2/introspect",
		},
		TokenEndpoint: config.TokenEndpoint{
			Endpoint:                     "employees/oauth2/token",
			AllowedAuthenticationMethods: []string{config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost},
		},
		UserInfoEndpoint: config.UserInfoEndpoint{
			Endpoint: "employees/oauth2/userinfo",
		},
		JWKSEndpoint: config.JWKSEndpoint{
			Endpoint: "employees/oauth2/jwks",
		},
		WellKnownEndpoint: config.WellKnownEndpoint{
			Endpoint: "employees/oauth2/.well-known/openid-configuration",
		},
		Keys: []crypto.PrivateKey{employeesKey},
	}

	employeesLoginApplication := config.Application{
		Name:                            "employees-login-application",
		Description:                     "Employees Login Application",
		Service:                         employeesService.Name,
		Public:                          false,
		RedirectURIs:                    []string{"http://localhost:8080/callback"},
		ResponseTypes:                   []string{config.ResponseTypeCode},
		GrantTypes:                      []string{config.GrantTypeAuthorizationCode},
		Scopes:                          []string{"openid", "profile", "offline_access"},
		PKCERequired:                    false,
		S256CodeChallengeMethodRequired: false,
		AllowedAuthenticationMethods:    []string{config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost},
	}

	employeesLoginApplicationCredentials := config.Credentials{
		Application:  employeesLoginApplication.Name,
		ClientID:     "employees-login-client-id",
		ClientSecret: "employees-login-client-secret",
	}

	m2mFirstKey := privateKey(t)
	m2mSecondKey := privateKey(t)
	m2mService := config.Service{
		Name:          "m2m",
		Identifier:    fmt.Sprintf("http://%s/m2m/", addr),
		Description:   "Machine to Machine Service",
		Scopes:        []string{"calendar:create", "calendar:read", "calendar:update", "calendar:delete"},
		GrantTypes:    []string{config.GrantTypeClientCredentials},
		ResponseTypes: []string{config.ResponseTypeCode},
		AuthorizationEndpoint: config.AuthorizationEndpoint{
			Endpoint: "m2m/oauth2/authorize",
		},
		IntrospectionEndpoint: config.IntrospectionEndpoint{
			Endpoint: "m2m/oauth2/introspect",
		},
		TokenEndpoint: config.TokenEndpoint{
			Endpoint:                     "m2m/oauth2/token",
			AllowedAuthenticationMethods: []string{config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost},
		},
		UserInfoEndpoint: config.UserInfoEndpoint{
			Endpoint: "m2m/oauth2/userinfo",
		},
		JWKSEndpoint: config.JWKSEndpoint{
			Endpoint: "m2m/oauth2/jwks",
		},
		WellKnownEndpoint: config.WellKnownEndpoint{
			Endpoint: "m2m/oauth2/.well-known/openid-configuration",
		},
		Keys: []crypto.PrivateKey{m2mFirstKey, m2mSecondKey},
	}

	notificationsApplication := config.Application{
		Name:                            "notifications",
		Service:                         m2mService.Name,
		Public:                          false,
		AllowedAuthenticationMethods:    []string{config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost},
		GrantTypes:                      []string{config.GrantTypeClientCredentials},
		ResponseTypes:                   []string{config.ResponseTypeCode},
		Scopes:                          []string{"calendar:read", "calendar:update"},
		PKCERequired:                    false,
		S256CodeChallengeMethodRequired: false,
	}

	notificationsCredentials := config.Credentials{
		Application:  notificationsApplication.Name,
		ClientID:     "notifications-client-id",
		ClientSecret: "notifications-client-secret",
	}

	onlyClientSecretBasic := config.Application{
		Name:                            "only-client-secret-basic",
		Service:                         m2mService.Name,
		Public:                          false,
		AllowedAuthenticationMethods:    []string{config.AuthenticationMethodClientSecretBasic},
		GrantTypes:                      []string{config.GrantTypeClientCredentials},
		ResponseTypes:                   []string{config.ResponseTypeCode},
		Scopes:                          []string{"calendar:read", "calendar:update"},
		PKCERequired:                    false,
		S256CodeChallengeMethodRequired: false,
	}

	onlyClientSecretBasicCredentials := config.Credentials{
		Application:  onlyClientSecretBasic.Name,
		ClientID:     "only-client-secret-basic-client-id",
		ClientSecret: "only-client-secret-basic-client-secret",
	}

	onlyClientSecretPost := config.Application{
		Name:                            "only-client-secret-post",
		Service:                         m2mService.Name,
		Public:                          false,
		AllowedAuthenticationMethods:    []string{config.AuthenticationMethodClientSecretPost},
		GrantTypes:                      []string{config.GrantTypeClientCredentials},
		ResponseTypes:                   []string{config.ResponseTypeCode},
		Scopes:                          []string{"calendar:read", "calendar:update"},
		PKCERequired:                    false,
		S256CodeChallengeMethodRequired: false,
	}

	onlyClientSecretPostCredentials := config.Credentials{
		Application:  onlyClientSecretPost.Name,
		ClientID:     "only-client-secret-post-client-id",
		ClientSecret: "only-client-secret-post-client-secret",
	}

	return TestConfig{
		Services:     []config.Service{firstService, customersService, employeesService, m2mService},
		Applications: []config.Application{testApp, loginApplication, publicApplication, s256RequiredApplication, helpdeskApplication, employeesLoginApplication, notificationsApplication, onlyClientSecretBasic, onlyClientSecretPost},
		Credentials:  []config.Credentials{firstCredentials, loginApplicationCredentials, publicCredentials, s256RequiredCredentials, helpdeskCredentials, employeesLoginApplicationCredentials, notificationsCredentials, onlyClientSecretBasicCredentials, onlyClientSecretPostCredentials},
	}
}
