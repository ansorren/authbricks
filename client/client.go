package client

import (
	"go.authbricks.com/bricks/database"
)

// Client allows you to interact with the AuthBricks data store.
type Client struct {
	DB *database.DB
}

// New creates a new client.
func New(db *database.DB) *Client {
	return &Client{
		DB: db,
	}
}
