package api

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAPI_JWKSHandler(t *testing.T) {
	t.Helper()
	testAPI, cancel := NewTestAPI(t)
	defer cancel(t)
	testAPI.Run(t)

	endpoint := fmt.Sprintf("http://%s/oauth2/jwks", testAPI.Address)

	resp, err := http.DefaultClient.Get(endpoint)
	require.Nil(t, err)
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}
