package api

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAPI_TokenHandler(t *testing.T) {
	t.Helper()
	testAPI, cancel := NewTestAPI(t)
	defer cancel(t)
	testAPI.Run(t)

	endpoint := fmt.Sprintf("http://%s/oauth2/token", testAPI.Address)

	resp, err := http.DefaultClient.Post(endpoint, "application/x-www-form-urlencoded", nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
