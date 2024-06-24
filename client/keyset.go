package client

import (
	"context"
	"crypto"
	"go.authbricks.com/bricks/ent"
	"go.authbricks.com/bricks/ent/keyset"
	"go.authbricks.com/bricks/ent/service"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// CreateKeySet creates a new key set for the given service.
func (c *Client) CreateKeySet(ctx context.Context, serviceName string, keys []crypto.PrivateKey) (*ent.KeySet, error) {
	svc, err := c.GetService(ctx, serviceName)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get service %s", serviceName)
	}
	keySet, err := c.DB.EntClient.KeySet.Create().
		SetService(svc).
		SetID(uuid.New().String()).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to create key set")
	}

	if err := c.CreateSigningKeysForKeySet(ctx, keySet, keys); err != nil {
		return nil, errors.Wrapf(err, "unable to create signing keys")
	}

	return keySet, nil

}

// GetKeySetByService returns the key set for the given service.
func (c *Client) GetKeySetByService(ctx context.Context, serviceName string) (*ent.KeySet, error) {
	svc, err := c.GetService(ctx, serviceName)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get service %s", serviceName)
	}

	return c.DB.EntClient.KeySet.Query().Where(keyset.HasServiceWith(service.ID(svc.ID))).Only(ctx)
}

func (c *Client) GetKeySetByID(ctx context.Context, keySetID string) (*ent.KeySet, error) {
	return c.DB.EntClient.KeySet.Query().Where(keyset.ID(keySetID)).Only(ctx)
}

// DeleteKeySet deletes a key set from the database.
func (c *Client) DeleteKeySet(ctx context.Context, keySetID string) error {
	keySet, err := c.GetKeySetByID(ctx, keySetID)
	if err != nil {
		return errors.Wrapf(err, "cannot delete key set %s - not found", keySetID)
	}

	// delete the signing keys first
	err = c.DeleteSigningKeysForKeySet(ctx, keySet)
	if err != nil {
		return errors.Wrapf(err, "cannot delete key set %s - unable to delete signing keys", keySetID)
	}

	return c.DB.EntClient.KeySet.DeleteOne(keySet).Exec(ctx)
}

// DeleteKeySetByService deletes the keyset for the given service.
func (c *Client) DeleteKeySetByService(ctx context.Context, serviceName string) error {
	ks, err := c.GetKeySetByService(ctx, serviceName)
	if err != nil {
		return errors.Wrapf(err, "cannot delete key set for service %s - not found", serviceName)
	}

	err = c.DeleteKeySet(ctx, ks.ID)
	if err != nil {
		return errors.Wrapf(err, "cannot delete key set for service %s", serviceName)
	}
	return nil
}
