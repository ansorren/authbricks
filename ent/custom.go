package ent

import (
	"strings"

	"github.com/pkg/errors"
)

const (
	ScopeOpenID  = "openid"
	ScopeProfile = "profile"
	ScopeEmail   = "email"
	ScopeAddress = "address"
	ScopePhone   = "phone"
)

// contains returns true if a slice of strings contains the given string.
func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// DefaultClaims returns all the default claims of a user.
// The default claims are defined in the OpenID Connect specification.
// https://openid.net/specs/openid-connect-basic-1_0.html#Scopes
func (s *StandardClaims) DefaultClaims() *StandardClaims {
	return &StandardClaims{
		Subject:           s.Subject,
		Name:              s.Name,
		FamilyName:        s.FamilyName,
		GivenName:         s.GivenName,
		MiddleName:        s.MiddleName,
		Nickname:          s.Nickname,
		PreferredUsername: s.PreferredUsername,
		Profile:           s.Profile,
		Picture:           s.Picture,
		Website:           s.Website,
		Gender:            s.Gender,
		Birthdate:         s.Birthdate,
		Zoneinfo:          s.Zoneinfo,
		Locale:            s.Locale,
		UpdatedAt:         s.UpdatedAt,
	}
}

// GetRequestedClaims returns the claims of a user based on the scopes requested.
func (s *StandardClaims) GetRequestedClaims(allowedScopes string) (*StandardClaims, error) {
	claims := &StandardClaims{
		Subject: s.Subject,
	}
	scopes := strings.Split(allowedScopes, " ")
	if !contains(scopes, ScopeOpenID) {
		return nil, errors.New("openid scope not present, but it is required")
	}

	// `profile` is defined as a scope that returns the default claims.
	if contains(scopes, ScopeProfile) {
		claims = s.DefaultClaims()
	}
	if contains(scopes, ScopeEmail) {
		claims.Email = s.Email
		claims.EmailVerified = s.EmailVerified
	}
	if contains(scopes, ScopeAddress) {
		claims.Address = s.Address
	}
	if contains(scopes, ScopePhone) {
		claims.PhoneNumber = s.PhoneNumber
		claims.PhoneNumberVerified = s.PhoneNumberVerified
	}

	return claims, nil
}
