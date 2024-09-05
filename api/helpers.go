package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

// generateRandomState generates a new random state to be used as the `state` value
// during an `authorization_code` flow.
func generateRandomState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	s := base64.StdEncoding.EncodeToString(b)
	return s, nil
}

// sanitiseEndpoint sanitises the endpoint by removing the base URL
// and any leading/trailing slashes.
func sanitiseEndpoint(endpoint string, baseURL string) string {
	if strings.HasPrefix(endpoint, baseURL) {
		newEndpoint := strings.TrimPrefix(endpoint, baseURL)
		return sanitiseEndpoint(newEndpoint, baseURL)
	}
	if strings.HasPrefix(endpoint, "/") {
		newEndpoint := strings.TrimPrefix(endpoint, "/")
		return sanitiseEndpoint(newEndpoint, baseURL)
	}
	if strings.HasSuffix(endpoint, "/") {
		newEndpoint := strings.TrimSuffix(endpoint, "/")
		return sanitiseEndpoint(newEndpoint, baseURL)
	}
	return endpoint
}

// sessionIsExpired checks if the given session is expired based on the given current time and duration.
func sessionIsExpired(session *ent.Session, duration time.Duration, now time.Time) bool {
	// Convert the CreatedAt field from int64
	sessionCreatedAt := time.Unix(session.CreatedAt, 0)

	// Calculate the expiration time by adding the session expiration duration to the CreatedAt time.
	expirationTime := sessionCreatedAt.Add(duration)

	// Check if the current time is after the expiration time.
	return now.After(expirationTime)
}

// Subject hashes the ID, so that it can be used as the `sub`
// field.
func Subject(id string) string {
	h := sha256.New()
	h.Write([]byte(id))
	return fmt.Sprintf("%x", h.Sum(nil))
}
