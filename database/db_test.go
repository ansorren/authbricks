package database

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// NewTestDB creates a new DB instance for testing. The second value returned is a cancel function
// that should be called when the test is complete.
func NewTestDB(t *testing.T) (*DB, func(*testing.T) error) {
	t.Helper()
	id := uuid.New().String()
	_ = os.MkdirAll(fmt.Sprintf("./%s", id), 0o755)
	path := fmt.Sprintf("./%s/%s.db", id, id)
	db, err := NewSQLite(context.Background(), path)
	require.Nil(t, err)
	return db, func(t *testing.T) error {
		t.Helper()
		err := db.Close()
		if err != nil {
			return err
		}
		err = os.RemoveAll(fmt.Sprintf("./%s", id))
		if err != nil {
			return err
		}
		return nil
	}
}
