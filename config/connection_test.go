package config

import "testing"

func TestNotUniqueOIDCConnectionNames(t *testing.T) {
	testCases := []struct {
		name     string
		oidc     []OIDCConnection
		expected bool
	}{
		{
			name:     "Unique names",
			oidc:     []OIDCConnection{{Name: "conn1"}, {Name: "conn2"}, {Name: "conn3"}},
			expected: false,
		},
		{
			name:     "Non-unique names",
			oidc:     []OIDCConnection{{Name: "conn1"}, {Name: "conn2"}, {Name: "conn1"}},
			expected: true,
		},
		{
			name:     "Empty list",
			oidc:     []OIDCConnection{},
			expected: false,
		},
		{
			name:     "Single entry",
			oidc:     []OIDCConnection{{Name: "conn1"}},
			expected: false,
		},
		{
			name:     "Multiple duplicates",
			oidc:     []OIDCConnection{{Name: "conn1"}, {Name: "conn2"}, {Name: "conn2"}, {Name: "conn1"}},
			expected: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			actual := notUniqueOIDCConnectionNames(tt.oidc)
			if actual != tt.expected {
				t.Errorf("got %v, want %v", actual, tt.expected)
			}
		})
	}
}

func TestConnection_Validate(t *testing.T) {
	testCases := []struct {
		Name          string
		Connection    Connection
		ExpectedError bool
	}{
		{
			Name: "No connections enabled / deemed valid",
			Connection: Connection{
				EmailPassword: nil,
				OIDC:          []OIDCConnection{},
			},
			ExpectedError: false,
		},
		{
			Name: "Invalid OIDC connection / not unique name",
			Connection: Connection{
				OIDC: []OIDCConnection{
					{
						Enabled: true,
						Name:    "some-name",
					},
					{
						Enabled: true,
						Name:    "some-name",
					},
				},
			},
			ExpectedError: true,
		},
		{
			Name: "Invalid OIDC connection / empty client ID",
			Connection: Connection{
				OIDC: []OIDCConnection{
					{
						Enabled:  true,
						Name:     "some-name",
						ClientID: "",
					},
				},
			},
			ExpectedError: true,
		},
		{
			Name: "Invalid OIDC connection / empty client secret",
			Connection: Connection{
				OIDC: []OIDCConnection{
					{
						Enabled:      true,
						Name:         "some-name",
						ClientID:     "some-client-id",
						ClientSecret: "",
					},
				},
			},
			ExpectedError: true,
		},
		{
			Name: "Invalid OIDC connection / empty scopes",
			Connection: Connection{
				OIDC: []OIDCConnection{
					{
						Enabled:      true,
						Name:         "some-name",
						ClientID:     "some-client-id",
						ClientSecret: "some-client-secret",
						Scopes:       []string{},
					},
				},
			},
			ExpectedError: true,
		},
		{
			Name: "Invalid OIDC connection / empty redirect URI",
			Connection: Connection{
				OIDC: []OIDCConnection{
					{
						Enabled:      true,
						Name:         "some-name",
						ClientID:     "some-client-id",
						ClientSecret: "some-client-secret",
						Scopes:       []string{"openid"},
						RedirectURI:  "",
					},
				},
			},
			ExpectedError: true,
		},
		{
			Name: "Invalid OIDC connection / empty well known endpoint",
			Connection: Connection{
				OIDC: []OIDCConnection{
					{
						Enabled:           true,
						Name:              "some-name",
						ClientID:          "some-client-id",
						ClientSecret:      "some-client-secret",
						Scopes:            []string{"openid"},
						RedirectURI:       "https://example.com/callback",
						WellKnownEndpoint: "",
					},
				},
			},
			ExpectedError: true,
		},
		{
			Name: "Valid connection",
			Connection: Connection{
				EmailPassword: &EmailPasswordConnection{
					Enabled: true,
				},
			},
			ExpectedError: false,
		},
		{
			Name: "Valid OIDC connection",
			Connection: Connection{
				OIDC: []OIDCConnection{
					{
						Enabled:           true,
						Name:              "some-name",
						ClientID:          "some-client-id",
						ClientSecret:      "some-client-secret",
						Scopes:            []string{"openid"},
						RedirectURI:       "https://example.com/callback",
						WellKnownEndpoint: "https://example.com/.well-known/openid-configuration",
					},
				},
			},
			ExpectedError: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			err := tc.Connection.Validate()
			if tc.ExpectedError && err == nil {
				t.Errorf("Expected error, got nil")
			}
			if !tc.ExpectedError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}
