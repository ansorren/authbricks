package database

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewSQLite(t *testing.T) {
	db, cancel := NewTestDB(t)
	defer func() {
		_ = cancel(t)
	}()
	err := db.EntClient.Close()
	require.Nil(t, err)
}
