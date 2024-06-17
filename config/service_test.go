package config

import (
	"testing"
)

func TestServiceValidate(t *testing.T) {
	tests := []struct {
		Name          string
		Service       Service
		ExpectedError bool
	}{
		{
			Name:          "empty Service",
			Service:       Service{},
			ExpectedError: true,
		},
		{
			Name:          "missing Service Name",
			Service:       Service{Identifier: "test"},
			ExpectedError: true,
		},
		{
			Name:          "missing Service identifier",
			Service:       Service{Name: "test"},
			ExpectedError: true,
		},
		{
			Name:          "missing Service Scopes",
			Service:       Service{Name: "test", Identifier: "test"},
			ExpectedError: true,
		},
		{
			Name: "at least one grant type is required",
			Service: Service{
				Name:       "test",
				Identifier: "test",
				Scopes:     []string{"test"},
			},
			ExpectedError: true,
		},
		{
			Name: "invalid grant type",
			Service: Service{
				Name:       "test",
				Identifier: "test",
				Scopes:     []string{"test"},
				GrantTypes: []string{"invalid"},
			},
			ExpectedError: true,
		},
		{
			Name: "valid Service",
			Service: Service{
				Name:       "test",
				Identifier: "test",
				Scopes:     []string{"test"},
				GrantTypes: []string{GrantTypeAuthorizationCode},
				ServiceMetadata: ServiceMetadata{
					"foo": "bar",
				},
			},
			ExpectedError: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			tt := tt
			if err := tt.Service.Validate(); (err != nil) != tt.ExpectedError {
				t.Errorf("Service.Validate() error = %v, ExpectedError %v", err, tt.ExpectedError)
			}
		})
	}
}
