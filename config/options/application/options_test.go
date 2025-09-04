package application

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.authbricks.com/bricks/config"
)

func TestNew(t *testing.T) {
	app := New("test-app")

	require.Equal(t, "test-app", app.Name)
	require.False(t, app.Public)
	require.False(t, app.PKCERequired)
	if len(app.ResponseTypes) != 1 || app.ResponseTypes[0] != config.ResponseTypeCode {
		t.Errorf("expected ResponseTypes to be [%s], got %v", config.ResponseTypeCode, app.ResponseTypes)
	}
	if len(app.GrantTypes) != 1 || app.GrantTypes[0] != config.GrantTypeAuthorizationCode {
		t.Errorf("expected GrantTypes to be [%s], got %v", config.GrantTypeAuthorizationCode, app.GrantTypes)
	}
	require.False(t, app.S256CodeChallengeMethodRequired)
}

func TestWithService(t *testing.T) {
	service := "test-service"
	app := New("app", WithService(service))

	if app.Service != service {
		t.Errorf("expected Service to be %s, got %s", service, app.Service)
	}
}

func TestWithDescription(t *testing.T) {
	description := "test description"
	app := New("app", WithDescription(description))

	if app.Description != description {
		t.Errorf("expected Description to be %s, got %s", description, app.Description)
	}
}

func TestIsPublic(t *testing.T) {
	app := New("app", IsPublic(true))

	if app.Public != true {
		t.Errorf("expected Public to be true, got %v", app.Public)
	}
}

func TestWithRedirectURIs(t *testing.T) {
	uris := []string{"https://example.com/callback", "https://example.com/callback2"}
	app := New("app", WithRedirectURIs(uris...))

	if len(app.RedirectURIs) != 2 {
		t.Errorf("expected 2 redirect URIs, got %d", len(app.RedirectURIs))
	}
	for i, uri := range uris {
		if app.RedirectURIs[i] != uri {
			t.Errorf("expected RedirectURIs[%d] to be %s, got %s", i, uri, app.RedirectURIs[i])
		}
	}
}

func TestWithResponseTypes(t *testing.T) {
	responseTypes := []string{config.ResponseTypeCode, config.ResponseTypeIDToken}
	app := New("app", WithResponseTypes(responseTypes...))

	if len(app.ResponseTypes) != 2 {
		t.Errorf("expected 2 response types, got %d", len(app.ResponseTypes))
	}
	for i, rt := range responseTypes {
		if app.ResponseTypes[i] != rt {
			t.Errorf("expected ResponseTypes[%d] to be %s, got %s", i, rt, app.ResponseTypes[i])
		}
	}
}

func TestWithGrantTypes(t *testing.T) {
	grantTypes := []string{config.GrantTypeAuthorizationCode, config.GrantTypeRefreshToken}
	app := New("app", WithGrantTypes(grantTypes...))

	if len(app.GrantTypes) != 2 {
		t.Errorf("expected 2 grant types, got %d", len(app.GrantTypes))
	}
	for i, gt := range grantTypes {
		if app.GrantTypes[i] != gt {
			t.Errorf("expected GrantTypes[%d] to be %s, got %s", i, gt, app.GrantTypes[i])
		}
	}
}

func TestWithPKCERequired(t *testing.T) {
	app := New("app", WithPKCERequired(true))

	if app.PKCERequired != true {
		t.Errorf("expected PKCERequired to be true, got %v", app.PKCERequired)
	}
}

func TestWithS256CodeChallengeMethodRequired(t *testing.T) {
	app := New("app", S256CodeChallengeMethodRequired(true))

	if app.S256CodeChallengeMethodRequired != true {
		t.Errorf("expected S256CodeChallengeMethodRequired to be true, got %v", app.S256CodeChallengeMethodRequired)
	}
}

func TestWithAllowedAuthenticationMethods(t *testing.T) {
	methods := []string{"password", "oauth"}
	app := New("app", WithAllowedAuthenticationMethods(methods...))

	if len(app.AllowedAuthenticationMethods) != 2 {
		t.Errorf("expected 2 authentication methods, got %d", len(app.AllowedAuthenticationMethods))
	}
	for i, method := range methods {
		if app.AllowedAuthenticationMethods[i] != method {
			t.Errorf("expected AllowedAuthenticationMethods[%d] to be %s, got %s", i, method, app.AllowedAuthenticationMethods[i])
		}
	}
}

func TestWithScopes(t *testing.T) {
	scopes := []string{"openid", "profile", "email"}
	app := New("app", WithScopes(scopes...))

	if len(app.Scopes) != 3 {
		t.Errorf("expected 3 scopes, got %d", len(app.Scopes))
	}
	for i, scope := range scopes {
		if app.Scopes[i] != scope {
			t.Errorf("expected Scopes[%d] to be %s, got %s", i, scope, app.Scopes[i])
		}
	}
}

func TestCompleteConfiguration(t *testing.T) {
	app := New("my-app",
		WithService("my-service"),
		WithDescription("My test application"),
		IsPublic(true),
		WithPKCERequired(true),
		WithRedirectURIs("https://example.com/callback"),
		WithResponseTypes(config.ResponseTypeCode, config.ResponseTypeIDToken),
		WithGrantTypes(config.GrantTypeAuthorizationCode, config.GrantTypeRefreshToken),
		S256CodeChallengeMethodRequired(true),
		WithAllowedAuthenticationMethods(config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost),
		WithScopes("openid", "profile"),
	)

	if app.Name != "my-app" {
		t.Errorf("expected Name to be 'my-app', got %s", app.Name)
	}
	if app.Service != "my-service" {
		t.Errorf("expected Service to be 'my-service', got %s", app.Service)
	}
	if app.Description != "My test application" {
		t.Errorf("expected Description to be 'My test application', got %s", app.Description)
	}
	if !app.Public {
		t.Errorf("expected Public to be true, got %v", app.Public)
	}
	if len(app.RedirectURIs) != 1 || app.RedirectURIs[0] != "https://example.com/callback" {
		t.Errorf("expected RedirectURIs to contain callback URL, got %v", app.RedirectURIs)
	}
	if len(app.GrantTypes) != 2 {
		t.Errorf("expected 2 grant types (default + added), got %d", len(app.GrantTypes))
	}
	if len(app.Scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(app.Scopes))
	}
	if !app.PKCERequired {
		t.Errorf("expected PKCERequired to be true, got %v", app.PKCERequired)
	}
}
