package client

import (
	"context"
	"crypto"
	"crypto/rsa"
	abcrypto "go.authbricks.com/bricks/crypto"
	"go.authbricks.com/bricks/ent/service"

	"go.authbricks.com/bricks/ent"
	"go.authbricks.com/bricks/ent/keyset"
	"go.authbricks.com/bricks/ent/signingkey"

	"github.com/pkg/errors"
)

// CreateSigningKey creates a new signing key for the given keyset.
func (c *Client) CreateSigningKey(ctx context.Context, ks *ent.KeySet, id string, key []byte) (*ent.SigningKey, error) {
	sk, err := c.DB.EntClient.SigningKey.Create().
		SetID(id).
		SetKeySet(ks).
		SetKey(string(key)).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to create signing key")
	}
	return sk, nil
}

// CreateSigningKeysForKeySet creates new signing keys for the given keyset.
func (c *Client) CreateSigningKeysForKeySet(ctx context.Context, ks *ent.KeySet, keys []crypto.PrivateKey) error {
	for _, key := range keys {
		// only RSA keys are supported
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return errors.New("only RSA keys are supported")
		}
		k, err := abcrypto.GeneratePEMFromRSAKey(rsaKey)
		if err != nil {
			return errors.Wrapf(err, "unable to generate PEM from RSA key")
		}

		keyID, err := abcrypto.GetKeyID(rsaKey.Public())
		if err != nil {
			return errors.Wrapf(err, "unable to generate key ID")
		}

		_, err = c.CreateSigningKey(ctx, ks, keyID, k)
		if err != nil {
			return errors.Wrapf(err, "unable to create key")
		}
	}
	return nil
}

// GetSigningKeyByID retrieves the signing key with the given ID.
func (c *Client) GetSigningKeyByID(ctx context.Context, keyID string) (*ent.SigningKey, error) {
	return c.DB.EntClient.SigningKey.Query().Where(signingkey.ID(keyID)).Only(ctx)
}

// GetSigningKeysByService retrieves all signing keys for the given service.
func (c *Client) GetSigningKeysByService(ctx context.Context, serviceName string) ([]*ent.SigningKey, error) {
	return c.DB.EntClient.SigningKey.Query().Where(signingkey.HasKeySetWith(keyset.HasServiceWith(service.Name(serviceName)))).All(ctx)
}

// DeleteSigningKeysForKeySet deletes all signing keys for the given keyset.
func (c *Client) DeleteSigningKeysForKeySet(ctx context.Context, ks *ent.KeySet) error {
	_, err := c.DB.EntClient.SigningKey.Delete().Where(signingkey.HasKeySetWith(keyset.ID(ks.ID))).Exec(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot delete signing keys for keyset %s", ks.ID)
	}
	return nil
}

// UpdateSigningKeysByService updates the signing keys for the given service.
func (c *Client) UpdateSigningKeysByService(ctx context.Context, serviceName string, keys []crypto.PrivateKey) error {
	// Update the signing keys
	// It is simply easier to delete all signing keys and recreate them
	// This is not the most efficient way and may need to be revisited

	keySet, err := c.GetKeySetByService(ctx, serviceName)
	if err != nil {
		return errors.Wrapf(err, "cannot get keyset for service %s", serviceName)
	}

	// Delete the signing keys
	err = c.DeleteSigningKeysForKeySet(ctx, keySet)
	if err != nil {
		return errors.Wrapf(err, "cannot delete signing keys for service %s", serviceName)
	}

	// Recreate the signing keys
	if err := c.CreateSigningKeysForKeySet(ctx, keySet, keys); err != nil {
		return errors.Wrapf(err, "unable to create signing keys")
	}
	return nil
}
