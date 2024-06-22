package database

import "go.authbricks.com/bricks/ent"

// DB is a wrapper around the ent client.
type DB struct {
	EntClient *ent.Client
}

// Close closes the connection.
func (db *DB) Close() error {
	return db.EntClient.Close()
}
