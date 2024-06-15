package db

import "go.authbricks.com/bricks/ent"

// DB is a wrapper around the ent client.
type DB struct {
	EntClient *ent.Client
}

// Client returns the ent client.
func (db *DB) Client() *ent.Client {
	return db.EntClient
}

// Close closes the connection.
func (db *DB) Close() error {
	return db.EntClient.Close()
}
