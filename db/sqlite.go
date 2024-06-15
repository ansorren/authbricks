package db

import (
	"context"
	"os"

	_ "github.com/mattn/go-sqlite3"
	"go.authbricks.com/bricks/ent"
)

// fileExists checks if a file exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// NewSQLite creates a new DB instance and will run the migrations.
func NewSQLite(ctx context.Context, path string) (*DB, error) {
	// if the database file does not exist, create it.
	if !fileExists(path) {
		_, err := os.Create(path)
		if err != nil {
			return nil, err
		}
	}

	// open the database file.
	entClient, err := ent.Open("sqlite3", "file:"+path+"?_fk=1")
	if err != nil {
		return nil, err
	}

	// run the schema migrations.
	if err := entClient.Schema.Create(ctx); err != nil {
		return nil, err
	}

	return &DB{
		EntClient: entClient,
	}, nil
}
