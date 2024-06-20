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
			Name: "empty redirect URIs",
			Application: Application{
				Name: "app",
			},
			ErrorExpected: true,
		},
		{
			Name: "redirect URIs with empty string",
			Application: Application{
				Name:         "app",
				RedirectURIs: []string{""},
			},
			ErrorExpected: true,
		},
		{
			Name: "empty response types",
			Application: Application{
				Name:          "app",
				RedirectURIs:  []string{"http://localhost:8080/callback"},
				ResponseTypes: []string{},
			},
			ErrorExpected: true,
		},
		{
			Name: "invalid response type",
			Application: Application{
				Name:          "app",
				RedirectURIs:  []string{"http://localhost:8080/callback"},
				ResponseTypes: []string{"invalid"},
			},
			ErrorExpected: true,
		},
		{
			Name: "empty grant types",
			Application: Application{
				Name:          "app",
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
				RedirectURIs:  []string{"http://localhost:8080/callback"},
				ResponseTypes: []string{"code"},
				GrantTypes:    []string{"invalid"},
			},
			ErrorExpected: true,
		},
		{
			Name: "valid",
			Application: Application{
				Name:          "app",
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
				t.Errorf("Application.Validate() error = %v, ErrorExpected %v", err, tt.ErrorExpected)
			}
		})
	}
}
