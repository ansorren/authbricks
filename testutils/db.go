package testutils

import (
	"context"
	"fmt"
	"os"
	"testing"

	"go.authbricks.com/bricks/database"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// DB creates a new DB instance for testing. The second value returned is a cancel function
// that should be called when the test is complete.
func DB(t *testing.T) (*database.DB, func(*testing.T)) {
	t.Helper()
	id := uuid.New().String()
	_ = os.MkdirAll(fmt.Sprintf("./%s", id), 0o755)
	path := fmt.Sprintf("./%s/%s.db", id, id)
	db, err := database.NewSQLite(context.Background(), path)
	require.Nil(t, err)
	return db, func(t *testing.T) {
		// attempt to close the database
		t.Helper()
		err := db.Close()
		if err != nil {
			fmt.Println(err)
			return
		}
		// attempt to remove the database file
		err = os.RemoveAll(fmt.Sprintf("./%s", id))
		if err != nil {
			fmt.Println(err)
			return
		}
		return
	}
}
