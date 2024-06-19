package config

// Application is used to configure an application.
type Application struct {
	Name          string
	RedirectURIs  []string
	ResponseTypes []string
	GrantTypes    []string
	// PKCERequired is true if the authorization endpoint requires PKCE, even for confidential clients.
	// Public clients are always required to use PKCE.
	PKCERequired bool
	// When S256CodeChallengeMethodRequired is true, the authorization endpoint requires the use of the S256 code challenge method.
	// This effectively disables the `plain` code challenge method.
	S256CodeChallengeMethodRequired bool
	// AllowedAuthenticationMethods is the list of allowed authentication methods.
	AllowedAuthenticationMethods []string

	// Scopes is the list of scopes that the application is allowed to request.
	// By default, if empty, the application is not allowed to request any scopes.
	Scopes []string
}