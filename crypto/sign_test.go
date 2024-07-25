package crypto

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gopkg.in/go-jose/go-jose.v2/jwt"
)

func TestSignAccessToken(t *testing.T) {
	pemKey, err := NewRSA4096PEMKey()
	require.Nil(t, err)
	key, err := GetRSAKeyFromPEM(pemKey)
	require.Nil(t, err)

	keys := []crypto.PublicKey{
		key.Public,
	}

	jwks, err := NewKeySet(keys)
	require.Nil(t, err)

	keyID := jwks.Keys[0].KeyID

	now := time.Now()
	tenMinutesInTheFuture := now.Add(10 * time.Minute)
	claims := jwt.Claims{
		Issuer:    "https://foo.com",
		Subject:   "bar@foo.com",
		Audience:  []string{"foo.com"},
		Expiry:    jwt.NewNumericDate(tenMinutesInTheFuture),
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        uuid.New().String(),
	}

	customClaims := struct {
		Scope    string           `json:"scope"`
		AuthTime *jwt.NumericDate `json:"auth_time,omitempty"`
	}{
		"foo bar",
		jwt.NewNumericDate(now),
	}

	token, err := SignAccessToken(key.Private, claims, customClaims, keyID)
	require.Nil(t, err)
	assertAccessTokenHeaderType(t, token)
	assertAuthTime(t, token, now)
}

func TestSignIDToken(t *testing.T) {
	pemKey, err := NewRSA4096PEMKey()
	require.Nil(t, err)
	key, err := GetRSAKeyFromPEM(pemKey)
	require.Nil(t, err)

	keys := []crypto.PublicKey{
		key.Public,
	}

	jwks, err := NewKeySet(keys)
	require.Nil(t, err)

	keyID := jwks.Keys[0].KeyID

	now := time.Now()
	tenMinutesInTheFuture := now.Add(10 * time.Minute)
	claims := jwt.Claims{
		Issuer:    "https://foo.com",
		Subject:   "bar@foo.com",
		Audience:  []string{"foo.com"},
		Expiry:    jwt.NewNumericDate(tenMinutesInTheFuture),
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        uuid.New().String(),
	}

	customClaims := struct {
		Scope    string           `json:"scope"`
		AuthTime *jwt.NumericDate `json:"auth_time,omitempty"`
	}{
		"foo bar",
		jwt.NewNumericDate(now),
	}

	token, err := SignIDToken(key.Private, claims, customClaims, keyID)
	require.Nil(t, err)
	fmt.Println(token)
	assertIDTokenHeaderType(t, token)
	assertAuthTime(t, token, now)
}

// assertIDTokenHeaderType asserts that the token type is "id_token+jwt".
func assertIDTokenHeaderType(t *testing.T, token string) {
	t.Helper()
	typ := getTokenHeaderType(t, token)
	require.Equal(t, JWTHeaderTypeIDToken, typ)
}

// assertAccessTokenHeaderType asserts that the token type is "at+JWT".
func assertAccessTokenHeaderType(t *testing.T, token string) {
	t.Helper()
	typ := getTokenHeaderType(t, token)
	require.Equal(t, JWTHeaderTypeAccessToken, typ)
}

// getTokenHeaderType returns the token type.
func getTokenHeaderType(t *testing.T, token string) string {
	t.Helper()
	// split the token into its parts
	parts := strings.Split(token, ".")
	require.Equal(t, 3, len(parts))
	// take the first part and decode it
	decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(parts[0])
	require.Nil(t, err)
	// unmarshal the decoded part into a map
	var m map[string]interface{}
	err = json.Unmarshal(decoded, &m)
	require.Nil(t, err)
	// assert the token type is "at+JWT"
	typ, ok := m["typ"].(string)
	require.True(t, ok)

	return typ
}

// assertAuthTime asserts that the auth_time claim is present in the token and
// that it has the expected value.
func assertAuthTime(t *testing.T, token string, expected time.Time) {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.Nil(t, err)
	var c struct {
		AuthTime *jwt.NumericDate `json:"auth_time,omitempty"`
	}
	err = json.Unmarshal(claims, &c)
	require.Nil(t, err)
	require.Equal(t, expected.Unix(), c.AuthTime.Time().Unix())
}
