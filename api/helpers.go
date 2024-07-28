package api

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"go.authbricks.com/bricks/ent"

	"github.com/pkg/errors"
)

const (
	AlphaNumericCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// AuthorizationCodeExpiration is the valid duration for an authorization code.
	AuthorizationCodeExpiration = 10 * time.Minute
)

// contains checks if the given string is in the given slice of strings.
func contains(slice []string, s string) bool {
	for _, a := range slice {
		if a == s {
			return true
		}
	}
	return false
}

// serviceAuthMethods returns the allowed authentication methods for the given service.
func (a *API) serviceAuthMethods(ctx context.Context, service *ent.Service) ([]string, error) {
	// get the service authentication methods
	cfg, err := service.QueryServiceTokenEndpointConfig().Only(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get token endpoint config")
	}
	return cfg.AllowedAuthenticationMethods, nil
}

// getGrantedScopes checks that all scopes we received from the payload
// are present in the slice of granted scopes. If the received scopes aren't specified
// we return all of the scopes in the app.
func getGrantedScopes(scopesFromPayload string, appScopes []string) (string, error) {
	// return all the granted scopes when the client does not explicitly request a subset
	if scopesFromPayload == "" {
		return strings.Join(appScopes, " "), nil
	}

	// client has requested a subset of scopes, validate that they've been granted each
	// and every single one of them
	requestedScopes := strings.Split(scopesFromPayload, " ")
	for _, requestedScope := range requestedScopes {
		if !contains(appScopes, requestedScope) {
			return "", fmt.Errorf("cannot request scope: %s", requestedScope)
		}
	}
	return scopesFromPayload, nil
}

// validateScopes validates the scopes granted are also present on the service.
func validateScopes(grantedScopes string, serviceScopes []string) error {
	s := strings.Split(grantedScopes, " ")
	for _, scope := range s {
		if !contains(serviceScopes, scope) {
			return fmt.Errorf("invalid scope: %s", scope)
		}
	}
	return nil
}

// randomString generates a random string of n characters using the given charset.
func randomString(n int, charset string) (string, error) {
	data := make([]byte, n)
	_, err := rand.Read(data)
	if err != nil {
		return "", errors.Wrapf(err, "unable to read data")
	}
	for k, v := range data {
		data[k] = charset[v%byte(len(charset))]
	}
	return string(data), nil
}

// randomAlphanumericString generates a secure string of n characters using the alphabetic charset.
func randomAlphanumericString(n int) (string, error) {
	return randomString(n, AlphaNumericCharset)
}

// codeIsExpired returns true if the authorization code expired.
func codeIsExpired(code *ent.AuthorizationCode, now time.Time) bool {
	elapsed := now.Sub(code.CreatedAt)
	if elapsed > AuthorizationCodeExpiration {
		return true
	}
	return false
}

// validateGrant returns an error if the application or the service are not allowed
// to use the given grant type.
func validateGrant(app *ent.Application, service *ent.Service, grantType string) error {
	if !contains(app.GrantTypes, grantType) {
		return fmt.Errorf("application %s is not allowed to use grant type: %s", app.Name, grantType)
	}
	if !contains(service.GrantTypes, grantType) {
		return fmt.Errorf("service %s is not allowed to use grant type: %s", service.Name, grantType)
	}
	return nil
}
