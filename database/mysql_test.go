package database

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestNewMySQL(t *testing.T) {
	_, shouldSkip := os.LookupEnv("AUTHBRICKS_SKIP_DOCKER_TESTS")
	if shouldSkip {
		t.Skip("POSTGRES_URL is not set")
	}
	db, err := NewMySQL(context.Background(), "user:pass@tcp(127.0.0.1:3306)/db?parseTime=True")
	require.Nil(t, err)

	client := db.EntClient
	creds, err := client.Credentials.Create().
		SetID(uuid.New().String()).
		SetClientID(uuid.New().String()).
		SetClientSecret(uuid.New().String()).
		Save(context.Background())
	require.Nil(t, err)

	_, err = client.Credentials.Get(context.Background(), creds.ID)
	require.Nil(t, err)

	all, err := client.Credentials.Query().All(context.Background())
	require.Nil(t, err)
	fmt.Println(all)
}
