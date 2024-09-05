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

func TestService(t *testing.T) {
	db, cancel := testutils.DB(t)
	defer cancel(t)

	key, err := abcrypto.GenerateRSAPrivateKey()
	require.Nil(t, err)

	client := New(db)
	require.NotNil(t, client)

	cfg := config.Service{
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

	svc, err := client.CreateService(context.Background(), cfg)
	require.Nil(t, err)
	require.NotNil(t, svc)
	require.NotEmpty(t, svc.ID)
	require.Equal(t, cfg.Name, svc.Name)
	require.Equal(t, cfg.Identifier, svc.Issuer)
	require.Equal(t, cfg.Description, svc.Description)
	require.Equal(t, cfg.AllowedClientMetadata, svc.AllowedClientMetadata)
	require.Equal(t, cfg.Scopes, svc.Scopes)
	require.Equal(t, cfg.GrantTypes, svc.GrantTypes)
	require.Equal(t, cfg.ResponseTypes, svc.ResponseTypes)

	// Authorization Endpoint
	authEndpointConfig, err := svc.QueryServiceAuthorizationEndpointConfig().Only(context.Background())
	require.Nil(t, err)
	require.NotNil(t, authEndpointConfig)
	require.Equal(t, cfg.AuthorizationEndpoint.Endpoint, authEndpointConfig.Endpoint)

	// Introspection Endpoint
	introspectionEndpointConfig, err := svc.QueryServiceIntrospectionEndpointConfig().Only(context.Background())
	require.Nil(t, err)
	require.NotNil(t, introspectionEndpointConfig)
	require.NotNil(t, introspectionEndpointConfig.ID)
	require.Equal(t, cfg.IntrospectionEndpoint.Endpoint, introspectionEndpointConfig.Endpoint)

	// Token Endpoint
	tokenEndpointConfig, err := svc.QueryServiceTokenEndpointConfig().Only(context.Background())
	require.Nil(t, err)
	require.NotNil(t, tokenEndpointConfig)
	require.NotNil(t, tokenEndpointConfig.ID)
	require.Equal(t, cfg.TokenEndpoint.Endpoint, tokenEndpointConfig.Endpoint)
	require.Equal(t, cfg.TokenEndpoint.AllowedAuthenticationMethods, tokenEndpointConfig.AllowedAuthenticationMethods)

	// User Info Endpoint
	userInfoEndpointConfig, err := svc.QueryServiceUserInfoEndpointConfig().Only(context.Background())
	require.Nil(t, err)
	require.NotNil(t, userInfoEndpointConfig)
	require.NotNil(t, userInfoEndpointConfig.ID)
	require.Equal(t, cfg.UserInfoEndpoint.Endpoint, userInfoEndpointConfig.Endpoint)

	// JWKs Endpoint
	jwksEndpointConfig, err := svc.QueryServiceJwksEndpointConfig().Only(context.Background())
	require.Nil(t, err)
	require.NotNil(t, jwksEndpointConfig)
	require.NotNil(t, jwksEndpointConfig.ID)
	require.Equal(t, cfg.JWKSEndpoint.Endpoint, jwksEndpointConfig.Endpoint)

	// Well Known Endpoint
	wellKnownEndpointConfig, err := svc.QueryServiceWellKnownEndpointConfig().Only(context.Background())
	require.Nil(t, err)
	require.NotNil(t, wellKnownEndpointConfig)
	require.NotNil(t, wellKnownEndpointConfig.ID)
	require.Equal(t, cfg.WellKnownEndpoint.Endpoint, wellKnownEndpointConfig.Endpoint)

	// Login Endpoint
	loginEndpointConfig, err := svc.QueryServiceLoginEndpointConfig().Only(context.Background())
	require.Nil(t, err)
	require.NotNil(t, loginEndpointConfig)
	require.NotNil(t, loginEndpointConfig.ID)
	require.Equal(t, cfg.LoginEndpoint.Endpoint, loginEndpointConfig.Endpoint)
	require.Equal(t, cfg.LoginEndpoint.SessionTimeout, time.Duration(loginEndpointConfig.SessionTimeout))
	// Update the service
	cfg.Description = "updated-description"
	svc, err = client.UpdateService(context.Background(), cfg)
	require.Nil(t, err)
	require.Equal(t, cfg.Description, svc.Description)

	// List services
	services, err := client.ListServices(context.Background())
	require.Nil(t, err)
	require.Len(t, services, 1)

	// Delete the service
	err = client.DeleteService(context.Background(), svc.Name)
	require.Nil(t, err)

	// List services again, should be empty
	services, err = client.ListServices(context.Background())
	require.Nil(t, err)
	require.Len(t, services, 0)
}
