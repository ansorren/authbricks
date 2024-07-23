package api

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

func TestAPI_JWKSHandler(t *testing.T) {
	t.Helper()
	testAPI, cancel := NewTestAPI(t)
	defer cancel(t)
	testAPI.Run(t)

	endpoint := fmt.Sprintf("http://%s/oauth2/jwks", testAPI.Address)

	resp, err := http.DefaultClient.Get(endpoint)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// unmarshal the response, assert that the keys are public
	u := NewUnmarshaler[jose.JSONWebKeySet](resp.Body)
	require.Nil(t, err)
	jwks, err := u.Unmarshal()
	require.Nil(t, err)
	require.Len(t, jwks.Keys, 2)
}
