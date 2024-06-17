package config

// Service is used to configure a service.
type Service struct {
	Name          string
	Scopes        []string
	GrantTypes    []string
	ResponseTypes []string
}
