package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRemovePadding(t *testing.T) {
	a := "foo==="
	b := removePadding(a)
	require.Equal(t, "foo", b)
}

func TestRandomHex(t *testing.T) {
	a := generateHexString(16)
	require.Len(t, a, 16)
}
