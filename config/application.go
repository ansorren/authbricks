package config

// Application is used to configure an application.
type Application struct {
	Name          string
	RedirectURIs  []string
	ResponseTypes []string
	GrantTypes    []string
}
