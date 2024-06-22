package database

import (
	"testing"

	"go.authbricks.com/bricks/testutils"

	"github.com/stretchr/testify/require"
)

func TestNewSQLite(t *testing.T) {
	db, cancel := testutils.DB(t)
	defer cancel(t)
	err := db.EntClient.Close()
	require.Nil(t, err)
}
