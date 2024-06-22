package client

import (
	"context"
	"testing"

	"go.authbricks.com/bricks/config"
	"go.authbricks.com/bricks/testutils"

	"github.com/stretchr/testify/require"
)

func TestCredentials(t *testing.T) {
	db, cancel := testutils.DB(t)
	defer cancel(t)

	client := New(db)
	require.NotNil(t, client)

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

	credsConfig := config.Credentials{
		Application:  app.Name,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
	}
	creds, err := client.CreateCredentials(context.Background(), credsConfig)
	require.Nil(t, err)
	require.NotNil(t, creds)
	require.NotEmpty(t, creds.ID)

}
