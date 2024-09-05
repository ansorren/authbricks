package client

import (
	"context"
	"crypto"
	"fmt"
	"testing"
	"time"

	"go.authbricks.com/bricks/config"
	abcrypto "go.authbricks.com/bricks/crypto"
	"go.authbricks.com/bricks/ent"
	"go.authbricks.com/bricks/ent/user"
	"go.authbricks.com/bricks/testutils"

	"github.com/stretchr/testify/require"
)

func Test_Connection_Empty(t *testing.T) {
	// this test starts with an empty connection
	// and then updates it to ensure that the connection
	// is properly validated and updated
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
		Connection: config.Connection{},
		Keys:       []crypto.PrivateKey{key},
	}

	fmt.Println("cfg", cfg)
	err = cfg.Validate()
	require.Nil(t, err)

	svc, err := client.CreateService(context.Background(), cfg)
	require.Nil(t, err)
	require.NotNil(t, svc)

	fmt.Println("svc", svc)
	// validate the connection configuration
	connectionConfig, err := svc.QueryServiceConnectionConfig().Only(context.Background())
	require.Nil(t, err)
	require.NotNil(t, connectionConfig)
	require.NotNil(t, connectionConfig.ID)

	// validate the email/password connection configuration
	_, err = connectionConfig.QueryEmailPasswordConnection().Only(context.Background())
	require.NotNil(t, err)
	require.True(t, ent.IsNotFound(err))

	fmt.Println("connectionConfig", connectionConfig)
	// create the email/password and the OIDC connections
	cfg.Connection.EmailPassword = &config.EmailPasswordConnection{
		Enabled: true,
	}
	cfg.Connection.OIDC = []config.OIDCConnection{
		{
			Enabled:           true,
			Name:              "conn-1",
			ClientID:          "some-client-id",
			ClientSecret:      "some-client-secret",
			Scopes:            []string{"openid"},
			RedirectURI:       "https://example.com/callback",
			WellKnownEndpoint: "https://example.com/.well-known/openid-configuration",
		},
		{
			Enabled:           true,
			Name:              "conn-2",
			ClientID:          "some-other-client-id",
			ClientSecret:      "some-other-client-secret",
			Scopes:            []string{"openid"},
			RedirectURI:       "http://localhost:8080/callback",
			WellKnownEndpoint: "https://example.com/.well-known/openid-configuration",
		},
	}
	svc, err = client.UpdateService(context.Background(), cfg)
	require.Nil(t, err)
	require.NotNil(t, svc)

	// validate the email/password connection configuration
	emailPasswordConnectionConfig, err := connectionConfig.QueryEmailPasswordConnection().Only(context.Background())
	require.Nil(t, err)
	require.NotNil(t, emailPasswordConnectionConfig)
	require.NotNil(t, emailPasswordConnectionConfig.ID)

	// validate the OIDC connections
	oidcConnections, err := connectionConfig.QueryOidcConnections().All(context.Background())
	require.Nil(t, err)
	require.Len(t, oidcConnections, 2)
	require.Equal(t, oidcConnections[0].ID, "conn-1")
	require.Equal(t, oidcConnections[1].ID, "conn-2")

	fmt.Println("before create user")
	// create users for the service
	u, err := client.CreateUser(context.Background(), CreateUserRequest{
		ConnectionType: ConnectionTypeEmailPassword,
		UserID:         "user-local-1",
		Username:       "test@example.com",
		Password:       "password",
		Service:        svc,
	})
	require.Nil(t, err)
	require.NotNil(t, u)

	fmt.Println("after create user")
	u, err = client.CreateUser(context.Background(), CreateUserRequest{
		ConnectionType: ConnectionTypeOIDC,
		UserID:         "oidc-user-1",
		Username:       "oidc-1@example.com",
		Password:       "password",
		Service:        svc,
		ConnectionName: "conn-1",
	})
	require.Nil(t, err)
	require.NotNil(t, u)

	u, err = client.CreateUser(context.Background(), CreateUserRequest{
		ConnectionType: ConnectionTypeOIDC,
		UserID:         "oidc-user-2",
		Username:       "oidc-2@example.com",
		Password:       "password",
		Service:        svc,
		ConnectionName: "conn-2",
	})
	require.Nil(t, err)
	require.NotNil(t, u)

	// delete the second OIDC connection
	// and only keep the first one
	cfg.Connection.OIDC = cfg.Connection.OIDC[:1]
	svc, err = client.UpdateService(context.Background(), cfg)
	require.Nil(t, err)

	// assert that the second connection was deleted
	oidcConnections, err = connectionConfig.QueryOidcConnections().All(context.Background())
	require.Nil(t, err)
	require.Len(t, oidcConnections, 1)
	require.Equal(t, oidcConnections[0].ID, "conn-1")

	// assert the users related to the deleted connection were also deleted
	u, err = oidcConnections[0].QueryUsers().Where(user.ID("oidc-user-2")).Only(context.Background())
	require.NotNil(t, err)
	require.True(t, ent.IsNotFound(err))

	// assert the users related to the remaining connection are still there
	u, err = oidcConnections[0].QueryUsers().Where(user.ID("oidc-user-1")).Only(context.Background())
	require.Nil(t, err)
	require.NotNil(t, u)
	require.Equal(t, u.ID, "oidc-user-1")

	// assert that disabling the email/password connection
	// does not delete the users
	cfg.Connection.EmailPassword.Enabled = false
	svc, err = client.UpdateService(context.Background(), cfg)
	require.Nil(t, err)
	require.NotNil(t, svc)

	emailPasswordConnectionConfig, err = connectionConfig.QueryEmailPasswordConnection().Only(context.Background())
	require.Nil(t, err)
	require.NotNil(t, emailPasswordConnectionConfig)

	u, err = emailPasswordConnectionConfig.QueryUsers().Where(user.ID("user-local-1")).Only(context.Background())
	require.Nil(t, err)
	require.NotNil(t, u)
	require.Equal(t, u.ID, "user-local-1")

	// assert that deleting the email/password connection
	// delete the email/password connection
	cfg.Connection.EmailPassword = nil
	svc, err = client.UpdateService(context.Background(), cfg)
	require.Nil(t, err)

	// assert that the email/password connection was deleted
	emailPasswordConnectionConfig, err = connectionConfig.QueryEmailPasswordConnection().Only(context.Background())
	require.NotNil(t, err)
	require.True(t, ent.IsNotFound(err))

	// assert that the users related to the email/password connection were also deleted
	u, err = client.GetUserByID(context.Background(), "user-local-1")
	require.NotNil(t, err)
	require.True(t, ent.IsNotFound(err))
}

func Test_Connection(t *testing.T) {
	// this test starts with both an email/password and an OIDC
	// connection and then updates the service configuration
	// to ensure that the connection
	// is properly validated and updated
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
			EmailPassword: &config.EmailPasswordConnection{
				Enabled: true,
			},
			OIDC: []config.OIDCConnection{
				{
					Enabled:           true,
					Name:              "conn-1",
					ClientID:          "some-client-id",
					ClientSecret:      "some-client-secret",
					Scopes:            []string{"openid"},
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

	// validate the connection configuration
	connectionConfig, err := svc.QueryServiceConnectionConfig().Only(context.Background())
	require.Nil(t, err)
	require.NotNil(t, connectionConfig)
	require.NotNil(t, connectionConfig.ID)

	// validate the email/password connection configuration
	emailPasswordConnectionConfig, err := connectionConfig.QueryEmailPasswordConnection().Only(context.Background())
	require.Nil(t, err)
	require.NotNil(t, emailPasswordConnectionConfig)
	require.NotNil(t, emailPasswordConnectionConfig.ID)
	require.Equal(t, cfg.Connection.EmailPassword.Enabled, emailPasswordConnectionConfig.Enabled)

	// validate the OIDC connection
	oidcConnections, err := connectionConfig.QueryOidcConnections().All(context.Background())
	require.Nil(t, err)
	require.Len(t, oidcConnections, 1)
	oidcConnection := oidcConnections[0]
	require.NotNil(t, oidcConnection.ID)
	require.Equal(t, cfg.Connection.OIDC[0].Enabled, oidcConnection.Enabled)
	require.Equal(t, cfg.Connection.OIDC[0].ClientID, oidcConnection.ClientID)
	require.Equal(t, cfg.Connection.OIDC[0].ClientSecret, oidcConnection.ClientSecret)
	require.Equal(t, cfg.Connection.OIDC[0].Scopes, oidcConnection.Scopes)
	require.Equal(t, cfg.Connection.OIDC[0].WellKnownEndpoint, oidcConnection.WellKnownOpenidConfiguration)

	newOIDCConnection := config.OIDCConnection{
		Enabled:           true,
		Name:              "conn-2",
		ClientID:          "some-other-client-id",
		ClientSecret:      "some-other-client-secret",
		Scopes:            []string{"openid"},
		RedirectURI:       "http://localhost:8080/callback",
		WellKnownEndpoint: "https://example.com/.well-known/openid-configuration",
	}
	// append another OIDC connection
	cfg.Connection.OIDC = append(cfg.Connection.OIDC, newOIDCConnection)
	svc, err = client.UpdateService(context.Background(), cfg)
	require.Nil(t, err)
	oidcConnections, err = connectionConfig.QueryOidcConnections().All(context.Background())
	require.Nil(t, err)
	require.Len(t, oidcConnections, 2)

	// create some users for the service
	u, err := client.CreateUser(context.Background(), CreateUserRequest{
		ConnectionType: ConnectionTypeEmailPassword,
		UserID:         "user-local-1",
		Username:       "test@example.com",
		Password:       "password",
		Service:        svc,
	})
	require.Nil(t, err)
	require.NotNil(t, u)

	u, err = client.CreateUser(context.Background(), CreateUserRequest{
		ConnectionType: ConnectionTypeOIDC,
		UserID:         "oidc-user-1",
		Username:       "test@example.com",
		Password:       "password",
		Service:        svc,
		ConnectionName: "conn-1",
	})
	require.Nil(t, err)
	require.NotNil(t, u)

	u, err = client.CreateUser(context.Background(), CreateUserRequest{
		ConnectionType: ConnectionTypeOIDC,
		UserID:         "oidc-user-2",
		Username:       "test2@example.com",
		Password:       "password",
		Service:        svc,
		ConnectionName: "conn-2",
	})
	require.Nil(t, err)
	require.NotNil(t, u)

	// delete the second OIDC connection
	// and only keep the first one
	cfg.Connection.OIDC = cfg.Connection.OIDC[:1]
	svc, err = client.UpdateService(context.Background(), cfg)
	require.Nil(t, err)

	// assert that the second connection was deleted
	oidcConnections, err = connectionConfig.QueryOidcConnections().All(context.Background())
	require.Nil(t, err)
	require.Len(t, oidcConnections, 1)
	require.Equal(t, oidcConnections[0].ID, "conn-1")

	// assert the users related to the deleted connection were also deleted
	u, err = oidcConnection.QueryUsers().Where(user.ID("oidc-user-2")).Only(context.Background())
	require.NotNil(t, err)
	require.True(t, ent.IsNotFound(err))

	// assert the users related to the remaining connection are still there
	u, err = oidcConnection.QueryUsers().Where(user.ID("oidc-user-1")).Only(context.Background())
	require.Nil(t, err)
	require.NotNil(t, u)
	require.Equal(t, u.ID, "oidc-user-1")

	// assert that disabling the email/password connection
	// does not delete the users
	cfg.Connection.EmailPassword.Enabled = false
	svc, err = client.UpdateService(context.Background(), cfg)
	require.Nil(t, err)
	require.NotNil(t, svc)

	emailPasswordConnectionConfig, err = connectionConfig.QueryEmailPasswordConnection().Only(context.Background())
	require.Nil(t, err)
	require.NotNil(t, emailPasswordConnectionConfig)

	u, err = emailPasswordConnectionConfig.QueryUsers().Where(user.ID("user-local-1")).Only(context.Background())
	require.Nil(t, err)
	require.NotNil(t, u)

	// assert that deleting the email/password connection
	// delete the email/password connection
	cfg.Connection.EmailPassword = nil
	svc, err = client.UpdateService(context.Background(), cfg)

	// assert that the email/password connection was deleted
	emailPasswordConnectionConfig, err = connectionConfig.QueryEmailPasswordConnection().Only(context.Background())
	require.NotNil(t, err)
	require.True(t, ent.IsNotFound(err))

	// assert that the users related to the email/password connection were also deleted
	u, err = client.GetUserByID(context.Background(), "user-local-1")
	require.NotNil(t, err)
	require.True(t, ent.IsNotFound(err))
}
