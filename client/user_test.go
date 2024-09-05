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

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func Test_User(t *testing.T) {
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
		LoginEndpoint: config.LoginEndpoint{
			Endpoint:       "/login",
			SessionTimeout: 30 * time.Minute,
		},
		Connection: config.Connection{
			EmailPassword: &config.EmailPasswordConnection{Enabled: true},
			OIDC: []config.OIDCConnection{
				{
					Enabled:           true,
					Name:              "oidc-conn-1",
					Scopes:            []string{"openid", "profile", "email"},
					ClientID:          "client-id",
					ClientSecret:      "client-secret",
					RedirectURI:       "https://example.com/callback",
					WellKnownEndpoint: "https://example.com/.well-known/openid-configuration",
				},
			},
		},
		Keys: []crypto.PrivateKey{key},
	}

	err = cfg.Validate()
	require.Nil(t, err)

	svc, err := client.CreateService(context.Background(), cfg)
	require.Nil(t, err)
	require.NotNil(t, svc)

	connectionConfig, err := svc.QueryServiceConnectionConfig().Only(context.Background())
	require.Nil(t, err)
	require.NotNil(t, connectionConfig)

	u, err := client.CreateUser(context.Background(), CreateUserRequest{
		ConnectionType: ConnectionTypeEmailPassword,
		UserID:         uuid.New().String(),
		Username:       "test@example.com",
		Password:       "password",
		Service:        svc,
		ConnectionName: "",
	})
	require.Nil(t, err)
	require.NotNil(t, u)

	u, err = client.GetUserByID(context.Background(), u.ID)
	require.Nil(t, err)
	require.NotNil(t, u)

	u.Username = "updated@example.com"
	u, err = client.UpdateUser(context.Background(), u)
	require.Nil(t, err)
	require.NotNil(t, u)
	require.Equal(t, "updated@example.com", u.Username)

	err = client.DeleteUser(context.Background(), u)
	require.Nil(t, err)

	u, err = client.GetUserByID(context.Background(), u.ID)
	require.NotNil(t, err)
	require.True(t, ent.IsNotFound(err))
}
