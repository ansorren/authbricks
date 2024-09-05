package api

import (
	"net/url"

	"go.authbricks.com/bricks/ent"
)

// AuthorizationContext is the context for the authorization request.
type AuthorizationContext struct {
	Service             *ent.Service
	Application         *ent.Application
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	RedirectURI         *url.URL
	GrantedScopes       []string
}
