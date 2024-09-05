package api

import (
	"fmt"
	"testing"

	"go.authbricks.com/bricks/ent"

	"github.com/stretchr/testify/assert"
)

func TestEnrichPayloadWithPKCEConfiguration(t *testing.T) {
	tests := []struct {
		name           string
		payload        *ent.AuthorizationPayload
		app            *ent.Application
		config         *ent.AuthorizationEndpointConfig
		expectedError  error
		expectedCode   string
		expectedMethod string
	}{
		{
			name:    "PKCE not required, no code challenge",
			payload: &ent.AuthorizationPayload{},
			app: &ent.Application{
				Public:                          false,
				PKCERequired:                    false,
				S256CodeChallengeMethodRequired: false,
			},
			config: &ent.AuthorizationEndpointConfig{
				PkceRequired:                        false,
				PkceS256CodeChallengeMethodRequired: false,
			},
			expectedError:  nil,
			expectedCode:   "",
			expectedMethod: "",
		},
		{
			name:    "PKCE required but no code challenge for public client",
			payload: &ent.AuthorizationPayload{},
			app: &ent.Application{
				Public:                          true,
				PKCERequired:                    true,
				S256CodeChallengeMethodRequired: false,
			},
			config: &ent.AuthorizationEndpointConfig{
				PkceRequired:                        true,
				PkceS256CodeChallengeMethodRequired: false,
			},
			expectedError:  fmt.Errorf("invalid request: missing code challenge"),
			expectedCode:   "",
			expectedMethod: "",
		},
		{
			name: "Code challenge present but method missing, plain allowed",
			payload: &ent.AuthorizationPayload{
				CodeChallenge: "test_challenge",
			},
			app: &ent.Application{
				Public:                          false,
				PKCERequired:                    true,
				S256CodeChallengeMethodRequired: false,
			},
			config: &ent.AuthorizationEndpointConfig{
				PkceRequired:                        true,
				PkceS256CodeChallengeMethodRequired: false,
			},
			expectedError:  nil,
			expectedCode:   "test_challenge",
			expectedMethod: PKCECodeChallengeMethodPlain,
		},
		{
			name: "Code challenge present but method missing, S256 required",
			payload: &ent.AuthorizationPayload{
				CodeChallenge: "test_challenge",
			},
			app: &ent.Application{
				Public:                          false,
				PKCERequired:                    true,
				S256CodeChallengeMethodRequired: true,
			},
			config: &ent.AuthorizationEndpointConfig{
				PkceRequired:                        true,
				PkceS256CodeChallengeMethodRequired: true,
			},
			expectedError:  nil,
			expectedCode:   "test_challenge",
			expectedMethod: PKCECodeChallengeMethodS256,
		},
		{
			name: "Invalid code challenge method",
			payload: &ent.AuthorizationPayload{
				CodeChallenge:       "test_challenge",
				CodeChallengeMethod: "unsupported_method",
			},
			app: &ent.Application{
				Public:                          false,
				PKCERequired:                    true,
				S256CodeChallengeMethodRequired: false,
			},
			config: &ent.AuthorizationEndpointConfig{
				PkceRequired:                        true,
				PkceS256CodeChallengeMethodRequired: false,
			},
			expectedError:  fmt.Errorf("invalid request: unsupported code challenge method: %s", "unsupported_method"),
			expectedCode:   "",
			expectedMethod: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := enrichPayloadWithPKCEConfiguration(tt.payload, tt.app, tt.config)

			if tt.expectedError != nil {
				assert.EqualError(t, err, tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedCode, payload.CodeChallenge)
				assert.Equal(t, tt.expectedMethod, payload.CodeChallengeMethod)
			}
		})
	}
}
