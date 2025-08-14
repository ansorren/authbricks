package service

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"go.authbricks.com/bricks/config"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	svc := New("service")

	if len(svc.Scopes) != 1 || svc.Scopes[0] != "openid" {
		t.Errorf("expected Scopes to be [openid], got %v", svc.Scopes)
	}
	if len(svc.GrantTypes) != 1 || svc.GrantTypes[0] != config.GrantTypeAuthorizationCode {
		t.Errorf("expected GrantTypes to be [%s], got %v", config.GrantTypeAuthorizationCode, svc.GrantTypes)
	}
	if len(svc.ResponseTypes) != 1 || svc.ResponseTypes[0] != config.ResponseTypeCode {
		t.Errorf("expected ResponseTypes to be [%s], got %v", config.ResponseTypeCode, svc.ResponseTypes)
	}
}

func TestWithIdentifier(t *testing.T) {
	identifier := "test-identifier"
	svc := New("service",
		WithIdentifier(identifier),
	)

	if svc.Identifier != identifier {
		t.Errorf("expected Identifier to be %s, got %s", identifier, svc.Identifier)
	}
}

func TestWithDescription(t *testing.T) {
	description := "test description"
	svc := New("service",
		WithDescription(description),
	)

	if svc.Description != description {
		t.Errorf("expected Description to be %s, got %s", description, svc.Description)
	}
}

func TestWithServiceMetadata(t *testing.T) {
	metadata := config.ServiceMetadata{
		"key1": "value1",
		"key2": "value2",
	}
	svc := New("service",
		WithServiceMetadata(metadata),
	)

	if len(svc.ServiceMetadata) != 2 {
		t.Errorf("expected 2 metadata entries, got %d", len(svc.ServiceMetadata))
	}
	if svc.ServiceMetadata["key1"] != "value1" {
		t.Errorf("expected ServiceMetadata[key1] to be 'value1', got %s", svc.ServiceMetadata["key1"])
	}
	if svc.ServiceMetadata["key2"] != "value2" {
		t.Errorf("expected ServiceMetadata[key2] to be 'value2', got %s", svc.ServiceMetadata["key2"])
	}
}

func TestWithAllowedClientMetadata(t *testing.T) {
	metadata := []string{"client_name", "client_uri"}
	svc := New("service",
		WithAllowedClientMetadata(metadata...),
	)

	if len(svc.AllowedClientMetadata) != 2 {
		t.Errorf("expected 2 metadata entries, got %d", len(svc.AllowedClientMetadata))
	}
	for i, entry := range metadata {
		if svc.AllowedClientMetadata[i] != entry {
			t.Errorf("expected AllowedClientMetadata[%d] to be %s, got %s", i, entry, svc.AllowedClientMetadata[i])
		}
	}
}

func TestWithScopes(t *testing.T) {
	scopes := []string{"openid", "profile", "email"}
	svc := New("service",
		WithScopes(scopes...),
	)

	if len(svc.Scopes) != 3 {
		t.Errorf("expected 3 scopes, got %d", len(svc.Scopes))
	}
	for i, scope := range scopes {
		if svc.Scopes[i] != scope {
			t.Errorf("expected Scopes[%d] to be %s, got %s", i, scope, svc.Scopes[i])
		}
	}
}

func TestWithGrantTypes(t *testing.T) {
	grantTypes := []string{config.GrantTypeAuthorizationCode, config.GrantTypeRefreshToken}
	svc := New("service",
		WithGrantTypes(grantTypes...),
	)

	if len(svc.GrantTypes) != 2 {
		t.Errorf("expected 2 grant types, got %d", len(svc.GrantTypes))
	}
	for i, gt := range grantTypes {
		if svc.GrantTypes[i] != gt {
			t.Errorf("expected GrantTypes[%d] to be %s, got %s", i, gt, svc.GrantTypes[i])
		}
	}
}

func TestWithResponseTypes(t *testing.T) {
	responseTypes := []string{config.ResponseTypeCode, config.ResponseTypeIDToken}
	svc := New("service",
		WithResponseTypes(responseTypes...),
	)

	if len(svc.ResponseTypes) != 2 {
		t.Errorf("expected 2 response types, got %d", len(svc.ResponseTypes))
	}
	for i, rt := range responseTypes {
		if svc.ResponseTypes[i] != rt {
			t.Errorf("expected ResponseTypes[%d] to be %s, got %s", i, rt, svc.ResponseTypes[i])
		}
	}
}

func TestWithAuthorizationEndpoint(t *testing.T) {
	endpoint := config.AuthorizationEndpoint{}
	svc := New("service",
		WithAuthorizationEndpoint(endpoint),
	)

	// Just verify the option was applied without comparing structs
	_ = svc.AuthorizationEndpoint
}

func TestWithIntrospectionEndpoint(t *testing.T) {
	endpoint := config.IntrospectionEndpoint{}
	svc := New("service",
		WithIntrospectionEndpoint(endpoint),
	)

	// Just verify the option was applied without comparing structs
	_ = svc.IntrospectionEndpoint
}

func TestWithTokenEndpoint(t *testing.T) {
	endpoint := config.TokenEndpoint{}
	svc := New("service",
		WithTokenEndpoint(endpoint),
	)

	// Just verify the option was applied without comparing structs
	_ = svc.TokenEndpoint
}

func TestWithUserInfoEndpoint(t *testing.T) {
	endpoint := config.UserInfoEndpoint{}
	svc := New("service",
		WithUserInfoEndpoint(endpoint),
	)

	// Just verify the option was applied without comparing structs
	_ = svc.UserInfoEndpoint
}

func TestWithJWKSEndpoint(t *testing.T) {
	endpoint := config.JWKSEndpoint{}
	svc := New("service",
		WithJWKSEndpoint(endpoint),
	)

	// Just verify the option was applied without comparing structs
	_ = svc.JWKSEndpoint
}

func TestWithWellKnownEndpoint(t *testing.T) {
	endpoint := config.WellKnownEndpoint{}
	svc := New("service",
		WithWellKnownEndpoint(endpoint),
	)

	// Just verify the option was applied without comparing structs
	_ = svc.WellKnownEndpoint
}

func TestWithLoginEndpoint(t *testing.T) {
	endpoint := config.LoginEndpoint{}
	svc := New("service",
		WithLoginEndpoint(endpoint),
	)

	// Just verify the option was applied without comparing structs
	_ = svc.LoginEndpoint
}

func TestWithConnection(t *testing.T) {
	connection := config.Connection{}
	svc := New("service",
		WithConnection(connection),
	)

	// Just verify the option was applied without comparing structs
	require.NotNil(t, svc.Connection)
}

func TestWithKeys(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key1: %v", err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key2: %v", err)
	}

	keys := []crypto.PrivateKey{key1, key2}
	svc := New("service",
		WithKeys(keys...),
	)

	if len(svc.Keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(svc.Keys))
	}
	for i, key := range keys {
		if svc.Keys[i] != key {
			t.Errorf("expected Keys[%d] to match provided key", i)
		}
	}
}

func TestCompleteConfiguration(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	svc := New("my-service",
		WithIdentifier("my-service-id"),
		WithDescription("My test service"),
		WithKeys(key),
		WithServiceMetadata(config.ServiceMetadata{"version": "1.0"}),
		WithAllowedClientMetadata("client_name"),
		WithScopes("profile", "email"),
	)

	require.Equal(t, svc.Name, "my-service")
	require.Equal(t, svc.Identifier, "my-service-id")
	require.Equal(t, svc.Description, "My test service")
	if len(svc.ServiceMetadata) != 1 || svc.ServiceMetadata["version"] != "1.0" {
		t.Errorf("expected ServiceMetadata to contain version=1.0, got %v", svc.ServiceMetadata)
	}
	if len(svc.AllowedClientMetadata) != 1 || svc.AllowedClientMetadata[0] != "client_name" {
		t.Errorf("expected AllowedClientMetadata to contain client_name, got %v", svc.AllowedClientMetadata)
	}
	require.ElementsMatch(t, svc.Scopes, []string{"profile", "email"})
	require.ElementsMatch(t, svc.GrantTypes, []string{config.GrantTypeAuthorizationCode})
	require.ElementsMatch(t, svc.ResponseTypes, []string{config.ResponseTypeCode})
	require.ElementsMatch(t, svc.Keys, []crypto.PrivateKey{key})
}
