package client

import (
	"context"
	"github.com/google/uuid"
	"go.authbricks.com/bricks/ent/application"

	"go.authbricks.com/bricks/config"
	"go.authbricks.com/bricks/ent"
	"go.authbricks.com/bricks/ent/credentials"

	"github.com/pkg/errors"
)

// CreateCredentials creates new credentials with the given configuration.
func (c *Client) CreateCredentials(ctx context.Context, cfg config.Credentials) (*ent.Credentials, error) {
	app, err := c.GetApplication(ctx, cfg.Application)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot create credentials for application %s - unable to get application", cfg.Application)
	}

	if err := cfg.Validate(app.Public); err != nil {
		return nil, errors.Wrapf(err, "cannot create credentials for application %s - invalid configuration", cfg.Application)
	}

	cred, err := c.DB.EntClient.Credentials.Create().
		SetID(uuid.New().String()).
		SetApplication(app).
		SetClientID(cfg.ClientID).
		SetClientSecret(cfg.ClientSecret).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot create credentials for application %s", cfg.Application)
	}

	return cred, nil
}

// GetCredentialsByApplication retrieves credentials associated with the given application.
func (c *Client) GetCredentialsByApplication(ctx context.Context, applicationName string) ([]*ent.Credentials, error) {
	return c.DB.EntClient.Credentials.Query().Where(credentials.HasApplicationWith(application.Name(applicationName))).All(ctx)
}

// GetCredentialsByClientID retrieves credentials with the given client ID.
func (c *Client) GetCredentialsByClientID(ctx context.Context, clientID string) (*ent.Credentials, error) {
	return c.DB.EntClient.Credentials.Query().Where(credentials.ClientID(clientID)).Only(ctx)
}

// GetCredentialsByID retrieves credentials with the given ID.
func (c *Client) GetCredentialsByID(ctx context.Context, id string) (*ent.Credentials, error) {
	return c.DB.EntClient.Credentials.Get(ctx, id)
}

// DeleteCredentialsByID deletes credentials with the given ID.
func (c *Client) DeleteCredentialsByID(ctx context.Context, id string) error {
	return c.DB.EntClient.Credentials.DeleteOneID(id).Exec(ctx)
}

// DeleteCredentialsByClientID deletes credentials with the given client ID.
func (c *Client) DeleteCredentialsByClientID(ctx context.Context, clientID string) error {
	cred, err := c.GetCredentialsByClientID(ctx, clientID)
	if err != nil {
		return errors.Wrapf(err, "cannot delete credentials for client ID %s", clientID)
	}

	return c.DB.EntClient.Credentials.DeleteOne(cred).Exec(ctx)
}

// DeleteCredentialsByApplication deletes all credentials for the given application.
func (c *Client) DeleteCredentialsByApplication(ctx context.Context, applicationName string) error {
	creds, err := c.GetCredentialsByApplication(ctx, applicationName)
	if err != nil {
		return errors.Wrapf(err, "cannot delete credentials for application %s", applicationName)
	}

	for _, cred := range creds {
		if err := c.DB.EntClient.Credentials.DeleteOne(cred).Exec(ctx); err != nil {
			return errors.Wrapf(err, "cannot delete credentials for application %s", applicationName)
		}
	}

	return nil
}

// UpdateCredentialsByID updates credentials with the given ID.
func (c *Client) UpdateCredentialsByID(ctx context.Context, id string, cfg config.Credentials) (*ent.Credentials, error) {
	cred, err := c.GetCredentialsByID(ctx, id)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot update credentials with ID %s - not found", id)
	}

	app, err := c.GetApplication(ctx, cfg.Application)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot update credentials with ID %s - unable to get application", id)
	}

	if err := cfg.Validate(app.Public); err != nil {
		return nil, errors.Wrapf(err, "cannot update credentials with ID %s - invalid configuration", id)
	}

	cred, err = c.DB.EntClient.Credentials.UpdateOne(cred).
		SetApplication(app).
		SetClientID(cfg.ClientID).
		SetClientSecret(cfg.ClientSecret).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot update credentials with ID %s", id)
	}

	return cred, nil
}

// UpdateCredentialsByClientID updates credentials with the given client ID found in the configuration.
func (c *Client) UpdateCredentialsByClientID(ctx context.Context, cfg config.Credentials) (*ent.Credentials, error) {
	cred, err := c.GetCredentialsByClientID(ctx, cfg.ClientID)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot update credentials for client ID %s - not found", cfg.ClientID)
	}

	app, err := c.GetApplication(ctx, cfg.Application)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot update credentials for client ID %s - unable to get application", cfg.ClientID)
	}

	if err := cfg.Validate(app.Public); err != nil {
		return nil, errors.Wrapf(err, "cannot update credentials for client ID %s - invalid configuration", cfg.ClientID)
	}

	cred, err = c.DB.EntClient.Credentials.UpdateOne(cred).
		SetApplication(app).
		SetClientID(cfg.ClientID).
		SetClientSecret(cfg.ClientSecret).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot update credentials for client ID %s", cfg.ClientID)
	}

	return cred, nil
}
