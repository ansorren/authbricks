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

// enrichPayloadWithPKCEConfiguration returns a new AuthorizationPayload enriched with the PKCE configuration.
func enrichPayloadWithPKCEConfiguration(payload *ent.AuthorizationPayload, app *ent.Application, config *ent.AuthorizationEndpointConfig) (*ent.AuthorizationPayload, error) {
	// PKCE is required if either the application or the service enforce it explicitly,
	// and must always be used when the application is public.
	pkceRequired := config.PkceRequired || app.PKCERequired || app.Public
	// S256 method is required if either the application or the service enforce it.
	s256Required := config.PkceS256CodeChallengeMethodRequired || app.S256CodeChallengeMethodRequired

	if !pkceRequired && payload.CodeChallengeMethod == "" && payload.CodeChallenge == "" {
		return payload, nil
	}

	// if PKCE is required, the code challenge is mandatory
	if payload.CodeChallenge == "" && pkceRequired {
		return nil, fmt.Errorf("invalid request: missing code challenge")
	}

	// If a code challenge is present, the code challenge method must also be set.
	// If it isn't, the code challenge method is set to `plain`, unless the S256 method is
	// required explicitly.
	if payload.CodeChallenge != "" && payload.CodeChallengeMethod == "" {
		if s256Required {
			payload.CodeChallengeMethod = PKCECodeChallengeMethodS256
		} else {
			payload.CodeChallengeMethod = PKCECodeChallengeMethodPlain
		}
	}

	// If the code challenge is present, the code challenge method must be one of the allowed methods.
	if payload.CodeChallenge != "" && !contains(allowedCodeChallengeMethods, payload.CodeChallengeMethod) {
		return nil, fmt.Errorf("invalid request: unsupported code challenge method: %s", payload.CodeChallengeMethod)
	}

	return payload, nil
}
