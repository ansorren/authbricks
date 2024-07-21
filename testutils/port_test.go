package testutils

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPort_Unused(t *testing.T) {
	first := unusedPort()

	// listen on the port, then put it back in the freePorts list.
	// This allows us to simulate a port that becomes used by another process.
	l, err := net.Listen("tcp", tcpAddr(localhost, first).String())
	require.Nil(t, err)
	defer func() {
		_ = l.Close()
	}()
	// the port should now be in use
	require.True(t, isPortInUse(first))

	// put the port back in the freePorts list
	freePorts.PushFront(first)

	// get another port
	// the two ports should not be the same
	second := unusedPort()
	require.NotEqual(t, first, second)

	require.False(t, isPortInUse(second))
}
