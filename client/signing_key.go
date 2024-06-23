package client

import (
	"context"

	"go.authbricks.com/bricks/ent"
	"go.authbricks.com/bricks/ent/keyset"
	"go.authbricks.com/bricks/ent/signingkey"

	"github.com/pkg/errors"
)

// DeleteSigningKeyForKeySet deletes all signing keys for the given keyset.
func (c *Client) DeleteSigningKeyForKeySet(ctx context.Context, ks *ent.KeySet) error {
	_, err := c.DB.EntClient.SigningKey.Delete().Where(signingkey.HasKeySetWith(keyset.ID(ks.ID))).Exec(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot delete signing keys for keyset %s", ks.ID)
	}
	return nil
}
