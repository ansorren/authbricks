package database

import (
	"context"

	_ "github.com/go-sql-driver/mysql"
	"go.authbricks.com/bricks/ent"
)

func NewMySQL(ctx context.Context, conn string) (*DB, error) {
	entClient, err := ent.Open("mysql", conn)
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
