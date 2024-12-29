package api

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAPI_WellKnownHandler(t *testing.T) {
	t.Helper()
	testAPI, cancel := NewTestAPI(t)
	defer cancel(t)
	testAPI.Run(t)

	endpoint := fmt.Sprintf("http://%s/oauth2/.well-known/openid-configuration", testAPI.Address)

	resp, err := http.DefaultClient.Get(endpoint)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	u := NewUnmarshaler[DiscoveryResponse](resp.Body)

	discoveryResponse, err := u.Unmarshal()
	require.Nil(t, err)

	fmt.Println(discoveryResponse)

	require.Equal(t, "test-identifier", discoveryResponse.Issuer)
	require.Equal(t, "http://127.0.0.1:20000/oauth2/authorize", discoveryResponse.AuthorizationEndpoint)
	require.Equal(t, "http://127.0.0.1:20000/oauth2/token", discoveryResponse.TokenEndpoint)
	require.Equal(t, "http://127.0.0.1:20000/oauth2/userinfo", discoveryResponse.UserInfoEndpoint)
	require.Equal(t, "http://127.0.0.1:20000/oauth2/jwks", discoveryResponse.JwksURI)
	require.ElementsMatch(t, []string{"openid"}, discoveryResponse.ScopesSupported)
	require.ElementsMatch(t, supportedResponseTypes, discoveryResponse.ResponseTypesSupported)
	require.ElementsMatch(t, supportedResponseModes, discoveryResponse.ResponseModesSupported)
	require.ElementsMatch(t, []string{"authorization_code", "client_credentials"}, discoveryResponse.GrantTypesSupported)
	require.ElementsMatch(t, supportedSubjectTypes, discoveryResponse.SubjectTypesSupported)
	require.ElementsMatch(t, supportedSigningAlgorithmValues, discoveryResponse.IDTokenSigningAlgValuesSupported)
	require.ElementsMatch(t, supportedSigningAlgorithmValues, discoveryResponse.UserInfoSigningAlgValuesSupported)
	require.ElementsMatch(t, []string{"client_secret_basic", "client_secret_post"}, discoveryResponse.TokenEndpointAuthMethodsSupported)
	require.ElementsMatch(t, claimsSupported, discoveryResponse.ClaimsSupported)
}
