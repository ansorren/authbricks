package db

import (
	"context"

	"go.authbricks.com/bricks/ent"
)

func NewPostgres(ctx context.Context, conn string) (*DB, error) {
	entClient, err := ent.Open("postgres", conn)
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
