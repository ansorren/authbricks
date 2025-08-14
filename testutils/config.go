package testutils

import (
	"crypto"
	"fmt"
	"testing"
	"time"

	"go.authbricks.com/bricks/config"
	"go.authbricks.com/bricks/config/options/application"
	"go.authbricks.com/bricks/config/options/credentials"
	"go.authbricks.com/bricks/config/options/service"
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

	firstService := service.New("test-service",
		service.WithIdentifier("test-identifier"),
		service.WithDescription("test-description"),
		service.WithGrantTypes(config.GrantTypeAuthorizationCode, config.GrantTypeClientCredentials),
		service.WithAuthorizationEndpoint(config.AuthorizationEndpoint{
			Endpoint:                        "/oauth2/authorize",
			PKCERequired:                    true,
			S256CodeChallengeMethodRequired: true,
		}),
		service.WithIntrospectionEndpoint(config.IntrospectionEndpoint{
			Endpoint: "/oauth2/introspect",
		}),
		service.WithTokenEndpoint(config.TokenEndpoint{
			Endpoint:                     "/oauth2/token",
			AllowedAuthenticationMethods: []string{config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost},
		}),
		service.WithUserInfoEndpoint(config.UserInfoEndpoint{
			Endpoint: "/oauth2/userinfo",
		}),
		service.WithJWKSEndpoint(config.JWKSEndpoint{
			Endpoint: "/oauth2/jwks",
		}),
		service.WithWellKnownEndpoint(config.WellKnownEndpoint{
			Endpoint: "/oauth2/.well-known/openid-configuration",
		}),
		service.WithLoginEndpoint(config.LoginEndpoint{
			Endpoint:       "/login",
			SessionTimeout: 24 * time.Hour,
		}),
		service.WithConnection(config.Connection{
			EmailPassword: &config.EmailPasswordConnection{
				Enabled: true,
			},
			OIDC: []config.OIDCConnection{
				{
					Enabled:           true,
					Name:              "oidc-connection-1",
					ClientID:          "test-client-id",
					ClientSecret:      "test-client-secret",
					RedirectURI:       fmt.Sprintf("http://%s/oauth2/callback", addr),
					Scopes:            []string{"openid", "profile", "email", "offline_access"},
					WellKnownEndpoint: fmt.Sprintf("http://127.0.0.1:3000/oauth2/.well-known/openid-configuration"),
				},
				{
					Enabled:           true,
					Name:              "oidc-connection-2",
					ClientID:          "test-client-id-2",
					ClientSecret:      "test-client-secret-2",
					RedirectURI:       fmt.Sprintf("http://%s/oauth2/callback", addr),
					Scopes:            []string{"openid", "profile", "email", "offline_access"},
					WellKnownEndpoint: fmt.Sprintf("http://127.0.0.1:3001/oauth2/.well-known/openid-configuration"),
				},
			},
		}),
		service.WithKeys(firstKey, secondKey),
	)

	testApp := application.New("test-application",
		application.WithDescription("test-description"),
		application.WithService(firstService.Name),
		application.WithAllowedAuthenticationMethods(config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost),
		application.WithRedirectURIs("http://localhost:8080/callback"),
		application.WithGrantTypes(config.GrantTypeAuthorizationCode, config.GrantTypeRefreshToken),
		application.WithScopes("openid"),
		application.WithPKCERequired(true),
	)

	firstCredentials := credentials.New(
		credentials.WithApplication(testApp.Name),
		credentials.WithClientID("test-client-id"),
		credentials.WithClientSecret("test-client-secret"),
	)

	customersKey := privateKey(t)
	customersService := service.New("customers",
		service.WithIdentifier(fmt.Sprintf("https://%s/customers", addr)),
		service.WithScopes("openid", "profile", "email", "offline_access", "customers:read"),
		service.WithGrantTypes(config.GrantTypeAuthorizationCode, config.GrantTypeRefreshToken, config.GrantTypeClientCredentials),
		service.WithResponseTypes(config.ResponseTypeCode, config.ResponseTypeIDToken, config.ResponseTypeCodeIDToken),
		service.WithAuthorizationEndpoint(config.AuthorizationEndpoint{
			Endpoint: "customers/oauth2/authorize",
		}),
		service.WithIntrospectionEndpoint(config.IntrospectionEndpoint{
			Endpoint: "customers/oauth2/introspect",
		}),
		service.WithTokenEndpoint(config.TokenEndpoint{
			Endpoint:                     "customers/oauth2/token",
			AllowedAuthenticationMethods: []string{config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost},
		}),
		service.WithUserInfoEndpoint(config.UserInfoEndpoint{
			Endpoint: "customers/oauth2/userinfo",
		}),
		service.WithJWKSEndpoint(config.JWKSEndpoint{
			Endpoint: "customers/oauth2/jwks",
		}),
		service.WithWellKnownEndpoint(config.WellKnownEndpoint{
			Endpoint: "customers/oauth2/.well-known/openid-configuration",
		}),
		service.WithLoginEndpoint(config.LoginEndpoint{
			Endpoint:       "customers/login",
			SessionTimeout: 24 * time.Hour,
		}),
		service.WithKeys(customersKey),
	)

	loginApplication := application.New("login-application",
		application.WithDescription("Login Application"),
		application.WithService(customersService.Name),
		application.WithRedirectURIs("http://localhost:8080/callback"),
		application.WithResponseTypes(config.ResponseTypeCode, config.ResponseTypeIDToken),
		application.WithGrantTypes(config.GrantTypeAuthorizationCode, config.GrantTypeRefreshToken),
		application.WithScopes("openid", "profile", "offline_access"),
		application.WithAllowedAuthenticationMethods(config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost),
	)

	loginApplicationCredentials := credentials.New(
		credentials.WithApplication(loginApplication.Name),
		credentials.WithClientID("login-client-id"),
		credentials.WithClientSecret("login-client-secret"),
	)

	publicApplication := application.New("public-client",
		application.WithDescription("Public Client"),
		application.IsPublic(true),
		application.WithService(customersService.Name),
		application.WithRedirectURIs("http://localhost:8080/callback"),
		application.WithGrantTypes(config.GrantTypeAuthorizationCode),
		application.WithScopes("openid", "profile", "offline_access"),
		application.WithPKCERequired(true),
		application.WithAllowedAuthenticationMethods(config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost),
	)

	publicCredentials := credentials.New(
		credentials.WithApplication(publicApplication.Name),
		credentials.WithClientID("publicApplication-client-id"),
	)

	s256RequiredApplication := application.New("s256-required",
		application.WithDescription("S256 Required"),
		application.IsPublic(true),
		application.WithService(customersService.Name),
		application.WithRedirectURIs("http://localhost:8080/callback"),
		application.WithGrantTypes(config.GrantTypeAuthorizationCode),
		application.WithScopes("openid", "profile", "offline_access"),
		application.WithPKCERequired(true),
		application.S256CodeChallengeMethodRequired(true),
		application.WithAllowedAuthenticationMethods(config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost),
	)

	s256RequiredCredentials := credentials.New(
		credentials.WithApplication(s256RequiredApplication.Name),
		credentials.WithClientID("s256-required-client-id"),
	)

	helpdeskApplication := application.New("helpdesk-application",
		application.WithDescription("Helpdesk Application"),
		application.WithService(customersService.Name),
		application.WithGrantTypes(config.GrantTypeClientCredentials),
		application.WithScopes("customers:read"),
		application.WithAllowedAuthenticationMethods(config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost),
	)

	helpdeskCredentials := credentials.New(
		credentials.WithApplication(helpdeskApplication.Name),
		credentials.WithClientID("helpdesk-client-id"),
		credentials.WithClientSecret("helpdesk-client-secret"),
	)

	employeesKey := privateKey(t)
	employeesService := service.New("employees",
		service.WithIdentifier(fmt.Sprintf("https://%s/employees", addr)),
		service.WithScopes("openid", "profile", "email", "offline_access"),
		service.WithGrantTypes(config.GrantTypeAuthorizationCode, config.GrantTypeRefreshToken, config.GrantTypeClientCredentials),
		service.WithResponseTypes(config.ResponseTypeCode, config.ResponseTypeIDToken, config.ResponseTypeIDToken),
		service.WithAuthorizationEndpoint(config.AuthorizationEndpoint{
			Endpoint: "employees/oauth2/authorize",
		}),
		service.WithIntrospectionEndpoint(config.IntrospectionEndpoint{
			Endpoint: "employees/oauth2/introspect",
		}),
		service.WithTokenEndpoint(config.TokenEndpoint{
			Endpoint:                     "employees/oauth2/token",
			AllowedAuthenticationMethods: []string{config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost},
		}),
		service.WithUserInfoEndpoint(config.UserInfoEndpoint{
			Endpoint: "employees/oauth2/userinfo",
		}),
		service.WithJWKSEndpoint(config.JWKSEndpoint{
			Endpoint: "employees/oauth2/jwks",
		}),
		service.WithWellKnownEndpoint(config.WellKnownEndpoint{
			Endpoint: "employees/oauth2/.well-known/openid-configuration",
		}),
		service.WithLoginEndpoint(config.LoginEndpoint{
			Endpoint:       "employees/login",
			SessionTimeout: 24 * time.Hour,
		}),
		service.WithKeys(employeesKey),
	)

	employeesLoginApplication := application.New("employees-login-application",
		application.WithDescription("Employees Login Application"),
		application.WithService(employeesService.Name),
		application.WithRedirectURIs("http://localhost:8080/callback"),
		application.WithGrantTypes(config.GrantTypeAuthorizationCode),
		application.WithScopes("openid", "profile", "offline_access"),
		application.WithAllowedAuthenticationMethods(config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost),
	)

	employeesLoginApplicationCredentials := credentials.New(
		credentials.WithApplication(employeesLoginApplication.Name),
		credentials.WithClientID("employees-login-client-id"),
		credentials.WithClientSecret("employees-login-client-secret"),
	)

	m2mFirstKey := privateKey(t)
	m2mSecondKey := privateKey(t)
	m2mService := service.New("m2m",
		service.WithIdentifier(fmt.Sprintf("http://%s/m2m/", addr)),
		service.WithDescription("Machine to Machine Service"),
		service.WithScopes("calendar:create", "calendar:read", "calendar:update", "calendar:delete"),
		service.WithGrantTypes(config.GrantTypeClientCredentials),
		service.WithAuthorizationEndpoint(config.AuthorizationEndpoint{
			Endpoint: "m2m/oauth2/authorize",
		}),
		service.WithIntrospectionEndpoint(config.IntrospectionEndpoint{
			Endpoint: "m2m/oauth2/introspect",
		}),
		service.WithTokenEndpoint(config.TokenEndpoint{
			Endpoint:                     "m2m/oauth2/token",
			AllowedAuthenticationMethods: []string{config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost},
		}),
		service.WithUserInfoEndpoint(config.UserInfoEndpoint{
			Endpoint: "m2m/oauth2/userinfo",
		}),
		service.WithJWKSEndpoint(config.JWKSEndpoint{
			Endpoint: "m2m/oauth2/jwks",
		}),
		service.WithWellKnownEndpoint(config.WellKnownEndpoint{
			Endpoint: "m2m/oauth2/.well-known/openid-configuration",
		}),
		service.WithLoginEndpoint(config.LoginEndpoint{
			Endpoint:       "m2m/login",
			SessionTimeout: 24 * time.Hour,
		}),
		service.WithKeys(m2mFirstKey, m2mSecondKey),
	)

	notificationsApplication := application.New("notifications",
		application.WithService(m2mService.Name),
		application.WithAllowedAuthenticationMethods(config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost),
		application.WithGrantTypes(config.GrantTypeClientCredentials),
		application.WithScopes("calendar:read", "calendar:update"),
	)

	notificationsCredentials := credentials.New(
		credentials.WithApplication(notificationsApplication.Name),
		credentials.WithClientID("notifications-client-id"),
		credentials.WithClientSecret("notifications-client-secret"),
	)

	onlyClientSecretBasic := application.New("only-client-secret-basic",
		application.WithService(m2mService.Name),
		application.WithAllowedAuthenticationMethods(config.AuthenticationMethodClientSecretBasic),
		application.WithGrantTypes(config.GrantTypeClientCredentials),
		application.WithScopes("calendar:read", "calendar:update"),
	)

	onlyClientSecretBasicCredentials := credentials.New(
		credentials.WithApplication(onlyClientSecretBasic.Name),
		credentials.WithClientID("only-client-secret-basic-client-id"),
		credentials.WithClientSecret("only-client-secret-basic-client-secret"),
	)

	onlyClientSecretPost := application.New("only-client-secret-post",
		application.WithService(m2mService.Name),
		application.WithAllowedAuthenticationMethods(config.AuthenticationMethodClientSecretPost),
		application.WithGrantTypes(config.GrantTypeClientCredentials),
		application.WithScopes("calendar:read", "calendar:update"),
	)

	onlyClientSecretPostCredentials := credentials.New(
		credentials.WithApplication(onlyClientSecretPost.Name),
		credentials.WithClientID("only-client-secret-post-client-id"),
		credentials.WithClientSecret("only-client-secret-post-client-secret"),
	)

	return TestConfig{
		Services:     []config.Service{firstService, customersService, employeesService, m2mService},
		Applications: []config.Application{testApp, loginApplication, publicApplication, s256RequiredApplication, helpdeskApplication, employeesLoginApplication, notificationsApplication, onlyClientSecretBasic, onlyClientSecretPost},
		Credentials:  []config.Credentials{firstCredentials, loginApplicationCredentials, publicCredentials, s256RequiredCredentials, helpdeskCredentials, employeesLoginApplicationCredentials, notificationsCredentials, onlyClientSecretBasicCredentials, onlyClientSecretPostCredentials},
	}
}
