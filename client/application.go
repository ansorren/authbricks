package client

import (
	"context"

	"go.authbricks.com/bricks/config"
	"go.authbricks.com/bricks/ent"
	"go.authbricks.com/bricks/ent/application"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// CreateApplication creates a new application.
func (c *Client) CreateApplication(ctx context.Context, cfg config.Application) (*ent.Application, error) {
	if err := cfg.Validate(); err != nil {
		return nil, errors.Wrapf(err, "cannot create application %s - invalid configuration", cfg.Name)
	}
	svc, err := c.GetService(ctx, cfg.Service)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot get service %s", cfg.Service)
	}

	return c.DB.EntClient.Application.Create().
		SetID(uuid.New().String()).
		SetService(svc).
		SetName(cfg.Name).
		SetPublic(cfg.Public).
		SetDescription(cfg.Description).
		SetRedirectUris(cfg.RedirectURIs).
		SetResponseTypes(cfg.ResponseTypes).
		SetGrantTypes(cfg.GrantTypes).
		SetScopes(cfg.Scopes).
		SetPKCERequired(cfg.PKCERequired).
		SetS256CodeChallengeMethodRequired(cfg.S256CodeChallengeMethodRequired).
		SetAllowedAuthenticationMethods(cfg.AllowedAuthenticationMethods).
		Save(ctx)
}

// GetApplication retrieves an application with the given name.
func (c *Client) GetApplication(ctx context.Context, name string) (*ent.Application, error) {
	return c.DB.EntClient.Application.Query().Where(application.Name(name)).Only(ctx)
}

// ListApplications retrieves all applications.
func (c *Client) ListApplications(ctx context.Context) ([]*ent.Application, error) {
	return c.DB.EntClient.Application.Query().All(ctx)
}

// DeleteApplication deletes an application with the given name.
func (c *Client) DeleteApplication(ctx context.Context, name string) error {
	app, err := c.GetApplication(ctx, name)
	if err != nil {
		return errors.Wrapf(err, "cannot delete application %s - not found", name)
	}

	// delete the application credentials first
	err = c.DeleteCredentialsByApplication(ctx, app.Name)
	if err != nil {
		return errors.Wrapf(err, "cannot delete application %s - unable to delete credentials", name)
	}

	return c.DB.EntClient.Application.DeleteOne(app).Exec(ctx)
}
