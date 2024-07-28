package api

import (
	"testing"
	"time"

	"go.authbricks.com/bricks/ent"
)

func TestRefreshTokenIsExpired(t *testing.T) {
	tests := []struct {
		name     string
		token    *ent.RefreshToken
		now      time.Time
		expected bool
	}{
		{
			name: "Token not expired",
			token: &ent.RefreshToken{
				CreatedAt: time.Now().Add(-1 * time.Hour).Unix(), // Created 1 hour ago
				Lifetime:  7200,                                  // Lifetime 2 hours
			},
			now:      time.Now(),
			expected: false,
		},
		{
			name: "Token expired",
			token: &ent.RefreshToken{
				CreatedAt: time.Now().Add(-3 * time.Hour).Unix(), // Created 3 hours ago
				Lifetime:  3600,                                  // Lifetime 1 hour
			},
			now:      time.Now(),
			expected: true,
		},
		{
			name: "Token just expired",
			token: &ent.RefreshToken{
				CreatedAt: time.Now().Add(-2 * time.Hour).Unix(), // Created 2 hours ago
				Lifetime:  7200,                                  // Lifetime 2 hours
			},
			now:      time.Now().Add(1 * time.Second), // Current time 1 second after expiration
			expected: true,
		},
		{
			name: "Token about to expire",
			token: &ent.RefreshToken{
				CreatedAt: time.Now().Unix(), // Created now
				Lifetime:  1,                 // Lifetime 1 second
			},
			now:      time.Now().Add(1 * time.Second), // Current time exactly at expiration
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := refreshTokenIsExpired(tt.token, tt.now)
			if got != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}
