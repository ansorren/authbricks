package config

import (
	"testing"
)

func TestApplication_Validate(t *testing.T) {
	tests := []struct {
		Name          string
		Application   Application
		ErrorExpected bool
	}{
		{
			Name:          "empty Name",
			Application:   Application{},
			ErrorExpected: true,
		},
		{
			Name: "empty service Name",
			Application: Application{
				Name: "app",
			},
			ErrorExpected: true,
		},
		{
			Name: "public application with PKCE not required",
			Application: Application{
				Name:         "app",
				Service:      "service",
				Public:       true,
				PKCERequired: false,
			},
			ErrorExpected: true,
		},
		{
			Name: "redirect URIs with empty string",
			Application: Application{
				Name:         "app",
				Service:      "service",
				RedirectURIs: []string{""},
			},
			ErrorExpected: true,
		},
		{
			Name: "empty response types",
			Application: Application{
				Name:          "app",
				Service:       "service",
				RedirectURIs:  []string{"http://localhost:8080/callback"},
				ResponseTypes: []string{},
			},
			ErrorExpected: true,
		},
		{
			Name: "empty response types with client credentials",
			Application: Application{
				Name:          "app",
				Service:       "service",
				ResponseTypes: []string{},
				GrantTypes:    []string{GrantTypeClientCredentials},
			},
			ErrorExpected: false,
		},
		{
			Name: "invalid response type",
			Application: Application{
				Name:          "app",
				Service:       "service",
				RedirectURIs:  []string{"http://localhost:8080/callback"},
				ResponseTypes: []string{"invalid"},
			},
			ErrorExpected: true,
		},
		{
			Name: "empty grant types",
			Application: Application{
				Name:          "app",
				Service:       "service",
				RedirectURIs:  []string{"http://localhost:8080/callback"},
				ResponseTypes: []string{"code"},
				GrantTypes:    []string{},
			},
			ErrorExpected: true,
		},
		{
			Name: "invalid grant type",
			Application: Application{
				Name:          "app",
				Service:       "service",
				RedirectURIs:  []string{"http://localhost:8080/callback"},
				ResponseTypes: []string{"code"},
				GrantTypes:    []string{"invalid"},
			},
			ErrorExpected: true,
		},
		{
			Name: "valid with no redirect URIs",
			Application: Application{
				Name:          "app",
				Service:       "service",
				ResponseTypes: []string{ResponseTypeCode},
				GrantTypes:    []string{GrantTypeAuthorizationCode},
			},
			ErrorExpected: false,
		},
		{
			Name: "valid",
			Application: Application{
				Name:          "app",
				Service:       "service",
				RedirectURIs:  []string{"http://localhost:8080/callback"},
				ResponseTypes: []string{ResponseTypeCode},
				GrantTypes:    []string{GrantTypeAuthorizationCode},
			},
			ErrorExpected: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			if err := tt.Application.Validate(); (err != nil) != tt.ErrorExpected {
				t.Errorf("Application.Validate() error = %v, Error Expected %v", err, tt.ErrorExpected)
			}
		})
	}
}
