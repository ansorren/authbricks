package client

import (
	"testing"

	"go.authbricks.com/bricks/testutils"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	db, cancel := testutils.DB(t)
	defer cancel(t)

	client := New(db)
	require.NotNil(t, client)
}
