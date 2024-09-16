package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"go.authbricks.com/bricks/client"

	"github.com/stretchr/testify/require"
)

func TestConnector(t *testing.T) {
	t.Helper()
	testAPI, cancel := NewTestAPI(t)
	defer cancel(t)
	testAPI.Run(t)

	c := client.New(testAPI.API.DB)
	service, err := c.GetService(context.Background(), "test-service")
	require.Nil(t, err)

	connectors, err := testAPI.API.getAvailableConnectors(context.Background(), service)
	require.Nil(t, err)
	require.Len(t, connectors, 3)
	require.Equal(t, connectorTypeEmailPassword, connectors[0].Type())
	require.Equal(t, connectorTypeOIDC, connectors[1].Type())
	require.Equal(t, connectorTypeOIDC, connectors[2].Type())

	loginEndpoint := fmt.Sprintf("http://%s/login", testAPI.Address)
	location, err := firstGETLoginRequest(t, loginEndpoint)
	require.Nil(t, err)

	resp, err := loginRequestWithSessionID(t, location)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	buf := new(strings.Builder)
	_, err = io.Copy(buf, resp.Body)
	require.Nil(t, err)
	// check errors
	fmt.Println(buf.String())
}
