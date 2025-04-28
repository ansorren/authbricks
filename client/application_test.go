package client

import (
	"context"
	"crypto"
	"testing"
	"time"

	"go.authbricks.com/bricks/config"
	abcrypto "go.authbricks.com/bricks/crypto"
	"go.authbricks.com/bricks/testutils"

	"github.com/stretchr/testify/require"
)

func TestApplication(t *testing.T) {
	db, cancel := testutils.DB(t)
	defer cancel(t)

	client := New(db)

	key, err := abcrypto.GenerateRSAPrivateKey()
	require.Nil(t, err)

	serviceConfig := config.Service{
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
			Endpoint:                        "https://example.com/oauth2/authorize",
			PKCERequired:                    true,
			S256CodeChallengeMethodRequired: true,
		},
		IntrospectionEndpoint: config.IntrospectionEndpoint{
			Endpoint: "https://example.com/oauth2/introspect",
		},
		TokenEndpoint: config.TokenEndpoint{
			Endpoint:                     "https://example.com/oauth2/token",
			AllowedAuthenticationMethods: []string{config.AuthenticationMethodClientSecretBasic, config.AuthenticationMethodClientSecretPost},
		},
		UserInfoEndpoint: config.UserInfoEndpoint{
			Endpoint: "https://example.com/oauth2/userinfo",
		},
		JWKSEndpoint: config.JWKSEndpoint{
			Endpoint: "https://example.com/oauth2/jwks",
		},
		WellKnownEndpoint: config.WellKnownEndpoint{
			Endpoint: "https://example.com/oauth2/.well-known/openid-configuration",
		},
		LoginEndpoint: config.LoginEndpoint{
			Endpoint:       "/login",
			SessionTimeout: 30 * time.Minute,
		},
		Keys: []crypto.PrivateKey{key},
	}

	svc, err := client.CreateService(context.Background(), serviceConfig)
	require.Nil(t, err)
	require.NotNil(t, svc)

	cfg := config.Application{
		Name:          "test-application",
		Description:   "test-description",
		Service:       svc.Name,
		Public:        false,
		RedirectURIs:  []string{"https://example.com/oauth2/callback"},
		ResponseTypes: []string{config.ResponseTypeCode},
		GrantTypes:    []string{config.GrantTypeAuthorizationCode},
		Scopes:        []string{"calendar:read"},
		PKCERequired:  true,
	}
	app, err := client.CreateApplication(context.Background(), cfg)
	require.Nil(t, err)
	require.NotNil(t, app)
	require.NotEmpty(t, app.ID)
	require.Equal(t, cfg.Name, app.Name)
	require.Equal(t, cfg.Description, app.Description)
	require.Equal(t, cfg.Public, app.Public)
	require.Equal(t, cfg.RedirectURIs, app.RedirectUris)
	require.Equal(t, cfg.ResponseTypes, app.ResponseTypes)
	require.Equal(t, cfg.GrantTypes, app.GrantTypes)
	require.Equal(t, cfg.Scopes, app.Scopes)
	require.Equal(t, cfg.PKCERequired, app.PKCERequired)

	// Get application
	app, err = client.GetApplication(context.Background(), cfg.Name)
	require.Nil(t, err)
	require.NotNil(t, app)

	// List applications - expected one
	apps, err := client.ListApplications(context.Background())
	require.Nil(t, err)
	require.NotNil(t, apps)
	require.Len(t, apps, 1)

	// Delete application
	err = client.DeleteApplication(context.Background(), cfg.Name)
	require.Nil(t, err)

	// List applications - expected none
	apps, err = client.ListApplications(context.Background())
	require.Nil(t, err)
	require.NotNil(t, apps)
	require.Len(t, apps, 0)

	// Test UpdateApplication
	updatedCfg := config.Application{
		Name:          "updated-application",
		Description:   "updated-description",
		Service:       svc.Name,
		Public:        true,
		RedirectURIs:  []string{"https://example.com/oauth2/updated-callback"},
		ResponseTypes: []string{config.ResponseTypeCode},
		GrantTypes:    []string{config.GrantTypeAuthorizationCode, config.GrantTypeClientCredentials},
		Scopes:        []string{"calendar:read", "calendar:write"},
		PKCERequired:  true,
	}

	// Create an application to update
	app, err = client.CreateApplication(context.Background(), cfg)
	require.Nil(t, err)
	require.NotNil(t, app)

	// Update the application
	updatedApp, err := client.UpdateApplication(context.Background(), cfg.Name, updatedCfg)
	require.Nil(t, err)
	require.NotNil(t, updatedApp)
	require.Equal(t, updatedCfg.Name, updatedApp.Name)
	require.Equal(t, updatedCfg.Description, updatedApp.Description)
	require.Equal(t, updatedCfg.Public, updatedApp.Public)
	require.Equal(t, updatedCfg.RedirectURIs, updatedApp.RedirectUris)
	require.Equal(t, updatedCfg.ResponseTypes, updatedApp.ResponseTypes)
	require.Equal(t, updatedCfg.GrantTypes, updatedApp.GrantTypes)
	require.Equal(t, updatedCfg.Scopes, updatedApp.Scopes)
	require.Equal(t, updatedCfg.PKCERequired, updatedApp.PKCERequired)

	// Test updating non-existent application
	_, err = client.UpdateApplication(context.Background(), "non-existent", updatedCfg)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "not found")

	// Test updating with invalid configuration
	invalidCfg := updatedCfg
	invalidCfg.Name = "" // Empty name is invalid
	_, err = client.UpdateApplication(context.Background(), updatedCfg.Name, invalidCfg)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "invalid configuration")

	// Test updating with non-existent service
	invalidServiceCfg := updatedCfg
	invalidServiceCfg.Service = "non-existent-service"
	_, err = client.UpdateApplication(context.Background(), updatedCfg.Name, invalidServiceCfg)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "unable to get service")

	// Test updating public application without PKCE
	invalidPKCECfg := updatedCfg
	invalidPKCECfg.PKCERequired = false
	_, err = client.UpdateApplication(context.Background(), updatedCfg.Name, invalidPKCECfg)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "public applications are required to use PKCE")
}
