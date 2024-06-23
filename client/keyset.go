package client

import (
	"context"
	"crypto/rsa"

	abcrypto "go.authbricks.com/bricks/crypto"
	"go.authbricks.com/bricks/ent"
	"go.authbricks.com/bricks/ent/keyset"
	"go.authbricks.com/bricks/ent/service"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// CreateKeySet creates a new key set for the given service.
func (c *Client) CreateKeySet(ctx context.Context, serviceName string, keys []*rsa.PrivateKey) (*ent.KeySet, error) {
	svc, err := c.GetService(ctx, serviceName)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get service %s", serviceName)
	}
	keySet, err := c.DB.EntClient.KeySet.Create().
		SetServices(svc).
		SetID(uuid.New().String()).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to create key set")
	}

	for _, key := range keys {
		k, err := abcrypto.GeneratePEMFromRSAKey(key)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to generate PEM from RSA key")
		}

		_, err = c.DB.EntClient.SigningKey.Create().
			SetID(uuid.New().String()).
			SetKeySet(keySet).
			SetKey(string(k)).
			Save(ctx)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to create key")
		}
	}
	return keySet, nil

}

// GetKeySetByService returns the key set for the given service.
func (c *Client) GetKeySetByService(ctx context.Context, serviceName string) ([]*ent.KeySet, error) {
	svc, err := c.GetService(ctx, serviceName)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get service %s", serviceName)
	}

	return c.DB.EntClient.KeySet.Query().Where(keyset.HasServicesWith(service.ID(svc.ID))).All(ctx)
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
	err = c.DeleteSigningKeyForKeySet(ctx, keySet)
	if err != nil {
		return errors.Wrapf(err, "cannot delete key set %s - unable to delete signing keys", keySetID)
	}

	return c.DB.EntClient.KeySet.DeleteOne(keySet).Exec(ctx)
}

// DeleteKeySetsByService deletes all keysets for the given service.
func (c *Client) DeleteKeySetsByService(ctx context.Context, serviceName string) error {
	keySets, err := c.GetKeySetByService(ctx, serviceName)
	if err != nil {
		return errors.Wrapf(err, "cannot delete key set for service %s - not found", serviceName)
	}

	for _, keySet := range keySets {
		err = c.DeleteKeySet(ctx, keySet.ID)
		if err != nil {
			return errors.Wrapf(err, "cannot delete key set for service %s", serviceName)
		}
	}
	return nil
}
