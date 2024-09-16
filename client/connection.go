package client

import (
	"context"

	"go.authbricks.com/bricks/config"
	"go.authbricks.com/bricks/ent"
	"go.authbricks.com/bricks/ent/connectionconfig"
	"go.authbricks.com/bricks/ent/oidcconnection"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// createConnectionConfig creates a new connection configuration for the given service.
func (c *Client) createConnectionConfig(ctx context.Context, service *ent.Service, cfg config.Connection) (*ent.ConnectionConfig, error) {
	// create the connection configuration
	connectionConfig, err := c.DB.EntClient.ConnectionConfig.Create().
		SetID(uuid.New().String()).
		SetService(service).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot create connection configuration for service %s", service.Name)
	}

	// create the email/password connection configuration
	if cfg.EmailPassword != nil {
		_, err = c.DB.EntClient.EmailPasswordConnection.Create().
			SetID(uuid.New().String()).
			SetEnabled(cfg.EmailPassword.Enabled).
			SetConnectionConfig(connectionConfig).
			Save(ctx)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot create email/password connection configuration for service %s", service.Name)
		}
	}

	// create the OIDC connection configuration
	for _, oidc := range cfg.OIDC {
		_, err = c.DB.EntClient.OIDCConnection.Create().
			SetID(oidc.Name).
			SetEnabled(oidc.Enabled).
			SetClientID(oidc.ClientID).
			SetClientSecret(oidc.ClientSecret).
			SetScopes(oidc.Scopes).
			SetRedirectURI(oidc.RedirectURI).
			SetWellKnownOpenidConfiguration(oidc.WellKnownEndpoint).
			SetConnectionConfig(connectionConfig).
			Save(ctx)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot create OIDC connection configuration for service %s", service.Name)
		}
	}
	return connectionConfig, nil
}

// updateEmailPasswordConnectionConfig updates the email/password connection configuration for the given service.
func (c *Client) updateEmailPasswordConnectionConfig(ctx context.Context, connConfig *ent.ConnectionConfig, emailPass *config.EmailPasswordConnection) error {
	switch {
	case emailPass == nil:
		emailPasswordConn, err := connConfig.QueryEmailPasswordConnection().Only(ctx)
		if ent.IsNotFound(err) {
			return nil
		}
		if err := c.deleteEmailPasswordConnection(ctx, emailPasswordConn); err != nil {
			return errors.Wrapf(err, "cannot delete email/password connection configuration")
		}
	case emailPass != nil:
		emailPasswordConn, err := connConfig.QueryEmailPasswordConnection().Only(ctx)
		switch {
		case ent.IsNotFound(err):
			// this means the email/password connection configuration does not exist
			// currently, and we need to create it for the first time
			emailPasswordConn, err = c.DB.EntClient.EmailPasswordConnection.Create().
				SetID(uuid.New().String()).
				SetEnabled(emailPass.Enabled).
				SetConnectionConfig(connConfig).
				Save(ctx)
			if err != nil {
				return errors.Wrapf(err, "cannot create email/password connection configuration")
			}
		case err != nil:
			return errors.Wrapf(err, "cannot query email/password connection configuration")
		}

		_, err = emailPasswordConn.Update().
			SetEnabled(emailPass.Enabled).
			Save(ctx)
		if err != nil {
			return errors.Wrapf(err, "cannot update email/password connection configuration")
		}
	}
	return nil
}

func (c *Client) updateOIDCConnectionConfig(ctx context.Context, connConfig *ent.ConnectionConfig, cfg config.Connection) error {
	oidcConns, err := connConfig.QueryOidcConnections().All(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot query OIDC connection configuration")
	}

	var currentOIDCConnections []string
	for _, oidc := range cfg.OIDC {
		currentOIDCConnections = append(currentOIDCConnections, oidc.Name)
	}
	// delete the existing OIDC connections that are not in the new configuration
	oidcToDelete, err := c.DB.EntClient.OIDCConnection.Query().
		Where(oidcconnection.HasConnectionConfigWith(connectionconfig.ID(connConfig.ID))).
		Where(oidcconnection.Not(oidcconnection.IDIn(currentOIDCConnections...))).
		All(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot get OIDC connection configuration")
	}
	for _, oidc := range oidcToDelete {
		err = c.deleteOIDCConnection(ctx, oidc)
		if err != nil {
			return errors.Wrapf(err, "cannot delete OIDC connection configuration %s ", oidc.ID)
		}
	}

	// update the existing OIDC connections
	for _, oidc := range oidcConns {
		for _, oidcConnection := range cfg.OIDC {
			if oidc.ID == oidcConnection.Name {
				_, err = oidc.Update().
					SetEnabled(oidcConnection.Enabled).
					SetClientID(oidcConnection.ClientID).
					SetClientSecret(oidcConnection.ClientSecret).
					SetScopes(oidcConnection.Scopes).
					SetRedirectURI(oidcConnection.RedirectURI).
					SetWellKnownOpenidConfiguration(oidcConnection.WellKnownEndpoint).
					Save(ctx)
				if err != nil {
					return errors.Wrapf(err, "cannot update OIDC connection configuration %s", oidcConnection.Name)
				}
			}
		}
	}

	// create the new OIDC connections
	for _, oidc := range cfg.OIDC {
		var found bool
		for _, oidcConn := range oidcConns {
			if oidcConn.ID == oidc.Name {
				found = true
				break
			}
		}
		if !found {
			_, err = c.DB.EntClient.OIDCConnection.Create().
				SetID(oidc.Name).
				SetEnabled(oidc.Enabled).
				SetClientID(oidc.ClientID).
				SetClientSecret(oidc.ClientSecret).
				SetScopes(oidc.Scopes).
				SetRedirectURI(oidc.RedirectURI).
				SetWellKnownOpenidConfiguration(oidc.WellKnownEndpoint).
				SetConnectionConfig(connConfig).
				Save(ctx)
			if err != nil {
				return errors.Wrapf(err, "cannot create OIDC connection configuration %s", oidc.Name)
			}
		}
	}
	return nil
}

// updateConnectionConfig updates the connection configuration for the given service.
func (c *Client) updateConnectionConfigForService(ctx context.Context, service *ent.Service, cfg config.Connection) (*ent.ConnectionConfig, error) {
	connConfig, err := service.QueryServiceConnectionConfig().Only(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot query connection configuration for service %s", service.Name)
	}
	if err := c.updateEmailPasswordConnectionConfig(ctx, connConfig, cfg.EmailPassword); err != nil {
		return nil, errors.Wrapf(err, "cannot update email/password connection configuration for service %s", service.Name)
	}
	if err := c.updateOIDCConnectionConfig(ctx, connConfig, cfg); err != nil {
		return nil, errors.Wrapf(err, "cannot update OIDC connection configuration for service %s", service.Name)
	}

	return connConfig, nil
}

// deleteOIDCConnection deletes the OIDC connection configuration.
func (c *Client) deleteOIDCConnection(ctx context.Context, oidc *ent.OIDCConnection) error {
	// delete the users first
	users, err := oidc.QueryUsers().All(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot query users for connection %s", oidc.ID)
	}
	for _, user := range users {
		err = c.DeleteUser(ctx, user)
		if err != nil {
			return errors.Wrapf(err, "cannot delete user %s", user.Username)
		}
	}
	// delete the OIDC connection
	err = c.DB.EntClient.OIDCConnection.DeleteOne(oidc).Exec(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot delete OIDC connection configuration for connection %s", oidc.ID)
	}
	return nil
}

// deleteEmailPasswordConnection deletes the email/password connection configuration.
func (c *Client) deleteEmailPasswordConnection(ctx context.Context, emailPassword *ent.EmailPasswordConnection) error {
	// delete the users first
	users, err := emailPassword.QueryUsers().All(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot query users")
	}

	for _, user := range users {
		err = c.DeleteUser(ctx, user)
		if err != nil {
			return errors.Wrapf(err, "cannot delete user %s", user.Username)
		}
	}

	// delete the email/password connection
	err = c.DB.EntClient.EmailPasswordConnection.DeleteOne(emailPassword).Exec(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot delete email/password connection configuration")
	}
	return nil
}

// deleteConnectionConfig deletes the connection configuration for the given service.
func (c *Client) deleteConnectionConfig(ctx context.Context, service *ent.Service) error {
	connConfig, err := service.QueryServiceConnectionConfig().Only(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot query connection configuration for service %s", service.Name)
	}

	emailPassword, err := connConfig.QueryEmailPasswordConnection().Only(ctx)
	switch {
	case ent.IsNotFound(err):
		// no email/password connection configuration
		// nothing to do
	case err != nil:
		return errors.Wrapf(err, "cannot query email/password connection configuration for service %s", service.Name)
	default:
		if err := c.deleteEmailPasswordConnection(ctx, emailPassword); err != nil {
			return errors.Wrapf(err, "cannot delete email/password connection configuration for service %s", service.Name)
		}
	}

	// delete the OIDC connections
	oidcConns, err := connConfig.QueryOidcConnections().All(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot query OIDC connection configuration for service %s", service.Name)
	}

	for _, oidc := range oidcConns {
		if err := c.deleteOIDCConnection(ctx, oidc); err != nil {
			return errors.Wrapf(err, "cannot delete OIDC connection configuration for service %s", service.Name)
		}
	}

	err = c.DB.EntClient.ConnectionConfig.DeleteOne(connConfig).Exec(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot delete connection configuration for service %s", service.Name)
	}
	return nil
}
