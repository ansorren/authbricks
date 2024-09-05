package api

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"go.authbricks.com/bricks/ent"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func newTestAuthorizationPayload(t *testing.T, testAPI TestAPI) *ent.AuthorizationPayload {
	t.Helper()
	creds := getCredentials(t, testAPI, "login-application")

	state, err := generateRandomState()
	require.Nil(t, err)

	codeVerifier, err := GeneratePKCECodeVerifier()
	require.Nil(t, err)
	codeChallenge := GeneratePKCECodeChallenge(codeVerifier)

	return &ent.AuthorizationPayload{
		ID:                  uuid.New().String(),
		ResponseType:        ResponseTypeAuthorizationCode,
		ResponseMode:        ResponseModeQuery,
		ClientID:            creds.ClientID,
		RedirectURI:         "http://localhost:8080/callback",
		Scope:               "openid profile email",
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: PKCECodeChallengeMethodS256,
		Nonce:               "foo",
		ServiceName:         "test-service",
	}
}

func TestAPI_ResumeAuthorizationHandler_Error(t *testing.T) {
	t.Helper()
	testAPI, cancel := NewTestAPI(t)
	defer cancel(t)

	testAPI.Run(t)

	twoDaysAgo := time.Now().Add(-2 * 24 * time.Hour).Unix()
	oneHourAgo := time.Now().Add(-1 * time.Hour).Unix()

	testCases := []struct {
		name           string
		sessionID      string
		session        *ent.Session
		payload        *ent.AuthorizationPayload
		expectedStatus int
		expectedError  string
	}{
		{
			name:      "Missing session ID",
			sessionID: "",
			session: &ent.Session{
				ID:          uuid.New().String(),
				CreatedAt:   oneHourAgo,
				ServiceName: "test-service",
			},
			payload:        newTestAuthorizationPayload(t, testAPI),
			expectedStatus: http.StatusBadRequest,
			expectedError:  "missing session ID",
		},
		{
			name:      "Session not found",
			sessionID: "nonexistent-session",
			session: &ent.Session{
				ID:          "123",
				CreatedAt:   oneHourAgo,
				ServiceName: "test-service",
			},
			payload:        newTestAuthorizationPayload(t, testAPI),
			expectedStatus: http.StatusBadRequest,
			expectedError:  "session not found",
		},
		{
			name:      "Session found but belongs to a different service",
			sessionID: "456",
			session: &ent.Session{
				ID:          "456",
				CreatedAt:   oneHourAgo,
				ServiceName: "some-other-service",
			},
			payload:        newTestAuthorizationPayload(t, testAPI),
			expectedStatus: http.StatusBadRequest,
			expectedError:  "session not found",
		},
		{
			name:      "Session expired",
			sessionID: "789",
			session: &ent.Session{
				ID:          "789",
				CreatedAt:   twoDaysAgo,
				ServiceName: "test-service",
			},
			payload:        newTestAuthorizationPayload(t, testAPI),
			expectedStatus: http.StatusBadRequest,
			expectedError:  "session expired",
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := testAPI.API.createSession(context.Background(), tc.session, tc.payload)
			require.Nil(t, err)
			resp, err := http.Get(fmt.Sprintf("http://%s/oauth2/authorize/resume?s=%s", testAPI.Address, tc.sessionID))
			require.Nil(t, err)
			require.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}
