package api

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// assertTokenLifetime asserts the lifetime of the token is the one we expect.
func assertTokenLifetime(t *testing.T, claims map[string]interface{}, expectedLifetime time.Duration) {
	t.Helper()
	i, ok := claims["iat"]
	require.True(t, ok)
	iat, ok := i.(float64)
	require.True(t, ok)
	issuedAt := time.Unix(int64(iat*1e9), 0)

	exp, ok := claims["exp"]
	require.True(t, ok)
	e, ok := exp.(float64)
	require.True(t, ok)
	expNano := int64(e * 1e9)

	duration := time.Duration(expNano - issuedAt.Unix())
	require.Equal(t, expectedLifetime, duration)
}

// writeFile is a helper function to write a file.
func writeFile(t *testing.T, fileName string, data []byte) {
	t.Helper()
	err := os.WriteFile(fileName, data, 0o644)
	require.Nil(t, err)
}

// deleteFile is a helper function to delete a file.
func deleteFile(t *testing.T, fileName string) {
	t.Helper()
	err := os.RemoveAll(fileName)
	require.Nil(t, err)
}
