package api

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"go.authbricks.com/bricks/client"
	"go.authbricks.com/bricks/testutils"

	"github.com/hashicorp/go-hclog"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestAPI_Action(t *testing.T) {
	env := map[string]any{
		"colour": "blue",
		"sub":    "1234567890",
		"aud":    "abc",
	}

	actions := []Action{
		{
			Name:        "test",
			Environment: env,
			ActionFunc: func(ctx context.Context, environment map[string]any, defaultClaims map[string]any) (map[string]any, error) {
				// inject the environment into the default claims
				// note how we can also override claims like "sub" or "aud"
				for k, v := range environment {
					defaultClaims[k] = v
				}
				return defaultClaims, nil
			},
		},
	}

	db, cancelDB := testutils.DB(t)
	defer cancelDB(t)
	c := client.New(db)

	address := testutils.LocalhostAddress()
	testCfg := testutils.NewTestConfig(t, address)
	for _, svc := range testCfg.Services {
		_, err := c.CreateService(context.Background(), svc)
		require.Nil(t, err)
	}
	for _, app := range testCfg.Applications {
		_, err := c.CreateApplication(context.Background(), app)
		require.Nil(t, err)
	}
	for _, cred := range testCfg.Credentials {
		_, err := c.CreateCredentials(context.Background(), cred)
		require.Nil(t, err)
	}
	logger := hclog.Default().Named("test")

	a, err := New(db, address,
		WithLogger(logger),
		WithBaseURL(fmt.Sprintf("http://%s", address)),
		WithAccessTokenActions(actions),
	)
	require.Nil(t, err)

	go func() {
		_ = a.Run(context.Background())
	}()
	time.Sleep(1 * time.Second)

	tokenEndpoint := fmt.Sprintf("http://%s/m2m/oauth2/token", a.Address)
	keySetEndpoint := fmt.Sprintf("http://%s/m2m/oauth2/jwks", a.Address)

	notificationsCredentials := getCredentials(t, a, "notifications")
	m2mKeySet := getKeySet(t, keySetEndpoint)
	aud := fmt.Sprintf("http://%s/m2m/", a.Address)

	testCases := []clientCredentialsTokenSuccessTestCase{
		{
			Name: "Success requesting default scopes",
			Payload: TokenPayload{
				ClientID:     notificationsCredentials.ClientID,
				ClientSecret: notificationsCredentials.ClientSecret,
				Audience:     aud,
				GrantType:    GrantTypeClientCredentials,
			},
			ExpectedScopes: []string{"calendar:read", "calendar:update"},
			KeySet:         m2mKeySet,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			req := prepareClientSecretPostRequest(t, tokenEndpoint, tc.Payload)
			r, err := http.DefaultClient.Do(req)
			require.Nil(t, err)
			require.Equal(t, http.StatusOK, r.StatusCode)
			require.Equal(t, "no-store", r.Header.Get(echo.HeaderCacheControl))
			require.Equal(t, "no-cache", r.Header.Get("Pragma"))

			u := NewUnmarshaler[TokenSuccessResponse](r.Body)
			tokenResponse, err := u.Unmarshal()
			require.Nil(t, err)
			fmt.Println(tokenResponse.AccessToken)
			claims, err := tc.KeySet.VerifySignature(context.Background(), tokenResponse.AccessToken)
			require.Nil(t, err)

			for k, v := range env {
				require.Equal(t, v, claims[k])
			}
		})
	}
}
