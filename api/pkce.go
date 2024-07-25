package api

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"go.authbricks.com/bricks/ent"
)

const (
	// PKCECodeChallengeMethodPlain is the `plain` code challenge method.
	PKCECodeChallengeMethodPlain = "plain"
	// PKCECodeChallengeMethodS256 is the `S256` code challenge method.
	PKCECodeChallengeMethodS256 = "S256"
	// PKCECodeVerifierLength is the length of the PKCE code verifier.
	PKCECodeVerifierLength = 128
)

// GeneratePKCECodeVerifier generates a PKCE code verifier (RFC 7636).
func GeneratePKCECodeVerifier() (string, error) {
	return randomAlphanumericString(PKCECodeVerifierLength)
}

// GeneratePKCECodeChallenge generates a PKCE code challenge.
func GeneratePKCECodeChallenge(codeVerifier string) string {
	s := sha256.New()
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(s.Sum([]byte(codeVerifier)))
}

// verifyPKCECodeChallengeMethod performs a PKCE verification of the code challenge.
func verifyPKCECodeChallenge(code *ent.AuthorizationCode, codeVerifier string, application *ent.Application) error {
	if code.CodeChallengeMethod == "" && application.PKCERequired {
		return fmt.Errorf("invalid request: code challenge method is required, but not provided")
	}
	// exit immediately if PKCE is not required and we don't have a code challenge
	if !application.PKCERequired && code.CodeChallengeMethod == "" {
		return nil
	}

	if len(codeVerifier) < 43 {
		return fmt.Errorf("invalid request: code verifier is too short - must be at least 43 characters")
	}

	if len(codeVerifier) > 128 {
		return fmt.Errorf("invalid request: code verifier is too long - must be 128 characters max")
	}

	switch code.CodeChallengeMethod {
	case PKCECodeChallengeMethodPlain:
		if application.S256CodeChallengeMethodRequired {
			return fmt.Errorf("invalid request: plain code challenge method not allowed")
		}
		// plain - verifier must match challenge
		if code.CodeChallenge != codeVerifier {
			return fmt.Errorf("invalid request: invalid code verifier - code challenge method: plain")
		}
	case PKCECodeChallengeMethodS256:
		// S256 - generate the challenge from the verifier and compare them
		if code.CodeChallenge != GeneratePKCECodeChallenge(codeVerifier) {
			return fmt.Errorf("invalid request: invalid code verifier - code challenge method: S256")
		}
	default:
		return fmt.Errorf("invalid request: invalid code challenge method: %s", code.CodeChallengeMethod)
	}
	return nil
}
