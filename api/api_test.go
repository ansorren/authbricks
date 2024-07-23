package api

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.authbricks.com/bricks/client"
	"go.authbricks.com/bricks/testutils"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

type TestAPI struct {
	API     *API
	Address string
}

func NewTestAPI(t *testing.T) (TestAPI, func(t *testing.T)) {
	t.Helper()
	db, cancelDB := testutils.DB(t)

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
		WithTLSEnabled(false))
	require.Nil(t, err)

	cancel := func(*testing.T) {
		cancelDB(t)
		_ = a.Close()
	}

	return TestAPI{
		API:     a,
		Address: address,
	}, cancel
}

func (api TestAPI) Run(t *testing.T) {
	t.Helper()
	go func() {
		err := api.API.Run(context.Background())
		require.Nil(t, err)
	}()
	time.Sleep(1 * time.Second)
}

func TestAPI_Run(t *testing.T) {
	t.Helper()
	testAPI, cancel := NewTestAPI(t)
	defer cancel(t)
	testAPI.Run(t)

}
