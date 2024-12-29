package api

import (
	"fmt"
	"net/http"
	"strings"

	"go.authbricks.com/bricks/ent"

	"github.com/labstack/echo/v4"
)

// claimsSupported is the list of claims supported by the OpenID Connect discovery endpoint.
var claimsSupported = []string{
	// JWT claims
	"iss",
	"sub",
	"aud",
	"exp",
	"nbf",
	"iat",
	"jti",
	"scope",
	"azp",
	// standard claims
	"name",
	"given_name",
	"family_name",
	"middle_name",
	"nickname",
	"preferred_username",
	"profile",
	"picture",
	"website",
	"email",
	"email_verified",
	"gender",
	"birthdate",
	"zoneinfo",
	"locale",
	"phone_number",
	"phone_number_verified",
	"address",
	"updated_at",
}

var (
	supportedSubjectTypes           = []string{"public", "pairwise"}
	supportedSigningAlgorithmValues = []string{"RS256"}
)

// DiscoveryResponse is the response of the OpenID Connect discovery endpoint.
type DiscoveryResponse struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	UserInfoSigningAlgValuesSupported []string `json:"userinfo_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
}

type DiscoveryErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func (a *API) WellKnownHandler(service *ent.Service) func(echo.Context) error {
	return func(c echo.Context) error {
		hostname := removeTrailingSlashes(a.BaseURL)

		authEndpointConfig, err := service.QueryServiceAuthorizationEndpointConfig().Only(c.Request().Context())
		if err != nil {
			return c.JSON(http.StatusInternalServerError, DiscoveryErrorResponse{
				Error:            "server error",
				ErrorDescription: "unable to get service authorization endpoint config",
			})
		}

		tokenEndpointConfig, err := service.QueryServiceTokenEndpointConfig().Only(c.Request().Context())
		if err != nil {
			return c.JSON(http.StatusInternalServerError, DiscoveryErrorResponse{
				Error:            "server error",
				ErrorDescription: "unable to get service token endpoint config",
			})
		}

		userInfoEndpointConfig, err := service.QueryServiceUserInfoEndpointConfig().Only(c.Request().Context())
		if err != nil {
			return c.JSON(http.StatusInternalServerError, DiscoveryErrorResponse{
				Error:            "server error",
				ErrorDescription: "unable to get service userinfo endpoint config",
			})
		}

		jwksEndpointConfig, err := service.QueryServiceJwksEndpointConfig().Only(c.Request().Context())
		if err != nil {
			return c.JSON(http.StatusInternalServerError, DiscoveryErrorResponse{
				Error:            "server error",
				ErrorDescription: "unable to get service jwks endpoint config",
			})
		}

		response := DiscoveryResponse{
			Issuer:                            service.Issuer,
			AuthorizationEndpoint:             fmt.Sprintf("%s/%s", hostname, removeLeadingSlashes(authEndpointConfig.Endpoint)),
			TokenEndpoint:                     fmt.Sprintf("%s/%s", hostname, removeLeadingSlashes(tokenEndpointConfig.Endpoint)),
			UserInfoEndpoint:                  fmt.Sprintf("%s/%s", hostname, removeLeadingSlashes(userInfoEndpointConfig.Endpoint)),
			JwksURI:                           fmt.Sprintf("%s/%s", hostname, removeLeadingSlashes(jwksEndpointConfig.Endpoint)),
			ScopesSupported:                   service.Scopes,
			ResponseTypesSupported:            supportedResponseTypes,
			ResponseModesSupported:            supportedResponseModes,
			GrantTypesSupported:               service.GrantTypes,
			SubjectTypesSupported:             supportedSubjectTypes,
			IDTokenSigningAlgValuesSupported:  supportedSigningAlgorithmValues,
			UserInfoSigningAlgValuesSupported: supportedSigningAlgorithmValues,
			TokenEndpointAuthMethodsSupported: tokenEndpointConfig.AllowedAuthenticationMethods,
			ClaimsSupported:                   claimsSupported,
		}

		return c.JSON(http.StatusOK, response)
	}
}

// removeTrailingSlashes removes the trailing slashes from the given string.
func removeLeadingSlashes(s string) string {
	return strings.TrimLeft(s, "/")
}
