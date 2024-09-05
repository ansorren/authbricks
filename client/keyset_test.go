package client

import (
	"context"
	"crypto"
	"testing"
	"time"

	"go.authbricks.com/bricks/config"
	abcrypto "go.authbricks.com/bricks/crypto"
	"go.authbricks.com/bricks/ent"
	"go.authbricks.com/bricks/testutils"

	"github.com/stretchr/testify/require"
)

func TestKeySet(t *testing.T) {
	db, cancel := testutils.DB(t)
	defer cancel(t)

	client := New(db)
	require.NotNil(t, client)

	key, err := abcrypto.GenerateRSAPrivateKey()
	require.Nil(t, err)

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

	keyset, err := client.GetKeySetByService(context.Background(), svc.Name)
	require.Nil(t, err)
	require.NotNil(t, keyset)
	require.NotEmpty(t, keyset)

	err = client.DeleteKeySetByService(context.Background(), svc.Name)
	require.Nil(t, err)

	_, err = client.GetKeySetByService(context.Background(), svc.Name)
	require.NotNil(t, err)
	require.True(t, ent.IsNotFound(err))
}
