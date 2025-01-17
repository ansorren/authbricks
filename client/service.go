package client

import (
	"context"
	"encoding/json"

	"go.authbricks.com/bricks/config"
	"go.authbricks.com/bricks/ent"
	"go.authbricks.com/bricks/ent/authorizationendpointconfig"
	"go.authbricks.com/bricks/ent/introspectionendpointconfig"
	"go.authbricks.com/bricks/ent/jwksendpointconfig"
	"go.authbricks.com/bricks/ent/loginendpointconfig"
	"go.authbricks.com/bricks/ent/service"
	"go.authbricks.com/bricks/ent/tokenendpointconfig"
	"go.authbricks.com/bricks/ent/userinfoendpointconfig"
	"go.authbricks.com/bricks/ent/wellknownendpointconfig"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// CreateService creates a new service in the database.
func (c *Client) CreateService(ctx context.Context, cfg config.Service) (*ent.Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, errors.Wrapf(err, "cannot create service %s - invalid configuration", cfg.Name)
	}

	// convert metadata to JSON, so we can store it in the database
	metadata, err := json.Marshal(cfg.ServiceMetadata)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot create service %s - invalid metadata", cfg.Name)
	}

	svc, err := c.DB.EntClient.Service.Create().
		SetID(uuid.New().String()).
		SetName(cfg.Name).
		SetIssuer(cfg.Identifier).
		SetDescription(cfg.Description).
		SetServiceMetadata(string(metadata)).
		SetAllowedClientMetadata(cfg.AllowedClientMetadata).
		SetScopes(cfg.Scopes).
		SetGrantTypes(cfg.GrantTypes).
		SetResponseTypes(cfg.ResponseTypes).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot create service %s", cfg.Name)
	}

	// create the authorization endpoint
	_, err = c.DB.EntClient.AuthorizationEndpointConfig.Create().
		SetID(uuid.New().String()).
		SetService(svc).
		SetEndpoint(cfg.AuthorizationEndpoint.Endpoint).
		SetPkceRequired(cfg.AuthorizationEndpoint.PKCERequired).
		SetPkceS256CodeChallengeMethodRequired(cfg.AuthorizationEndpoint.S256CodeChallengeMethodRequired).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot create authorization endpoint configuration for service %s", cfg.Name)
	}

	// create the introspection endpoint
	_, err = c.DB.EntClient.IntrospectionEndpointConfig.Create().
		SetID(uuid.New().String()).
		SetService(svc).
		SetEndpoint(cfg.IntrospectionEndpoint.Endpoint).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot create introspection endpoint configuration for service %s", cfg.Name)
	}

	// create the token endpoint
	_, err = c.DB.EntClient.TokenEndpointConfig.Create().
		SetID(uuid.New().String()).
		SetService(svc).
		SetEndpoint(cfg.TokenEndpoint.Endpoint).
		SetAllowedAuthenticationMethods(cfg.TokenEndpoint.AllowedAuthenticationMethods).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot create token endpoint configuration for service %s", cfg.Name)
	}

	// create the user info endpoint
	_, err = c.DB.EntClient.UserInfoEndpointConfig.Create().
		SetID(uuid.New().String()).
		SetService(svc).
		SetEndpoint(cfg.UserInfoEndpoint.Endpoint).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot create user info endpoint configuration for service %s", cfg.Name)
	}

	// create the JWKS endpoint
	_, err = c.DB.EntClient.JwksEndpointConfig.Create().
		SetID(uuid.New().String()).
		SetService(svc).
		SetEndpoint(cfg.JWKSEndpoint.Endpoint).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot create JWKS endpoint configuration for service %s", cfg.Name)
	}
	// create the well known endpoint
	_, err = c.DB.EntClient.WellKnownEndpointConfig.Create().
		SetID(uuid.New().String()).
		SetService(svc).
		SetEndpoint(cfg.WellKnownEndpoint.Endpoint).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot create well known endpoint configuration for service %s", cfg.Name)
	}
	// create the login endpoint
	_, err = c.DB.EntClient.LoginEndpointConfig.Create().
		SetID(uuid.New().String()).
		SetService(svc).
		SetEndpoint(cfg.LoginEndpoint.Endpoint).
		SetSessionTimeout(int64(cfg.LoginEndpoint.SessionTimeout)).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot create login endpoint configuration for service %s", cfg.Name)
	}

	// create the connection configuration
	_, err = c.createConnectionConfig(ctx, svc, cfg.Connection)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot create connection configuration for service %s", cfg.Name)
	}

	// create the key set
	_, err = c.CreateKeySet(ctx, cfg.Name, cfg.Keys)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot create keyset for service %s", cfg.Name)
	}

	return svc, nil
}

// GetService retrieves the service with the given name from the database.
func (c *Client) GetService(ctx context.Context, name string) (*ent.Service, error) {
	return c.DB.EntClient.Service.Query().Where(service.Name(name)).Only(ctx)
}

// DeleteService deletes a service from the database.
func (c *Client) DeleteService(ctx context.Context, name string) error {
	svc, err := c.GetService(ctx, name)
	if err != nil {
		return errors.Wrapf(err, "cannot delete service %s", name)
	}

	_, err = c.DB.EntClient.AuthorizationEndpointConfig.Delete().Where(authorizationendpointconfig.HasServiceWith(service.ID(svc.ID))).Exec(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot delete authorization endpoint configuration for service %s", name)
	}

	_, err = c.DB.EntClient.IntrospectionEndpointConfig.Delete().Where(introspectionendpointconfig.HasServiceWith(service.ID(svc.ID))).Exec(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot delete introspection endpoint configuration for service %s", name)
	}

	_, err = c.DB.EntClient.TokenEndpointConfig.Delete().Where(tokenendpointconfig.HasServiceWith(service.ID(svc.ID))).Exec(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot delete token endpoint configuration for service %s", name)
	}

	_, err = c.DB.EntClient.UserInfoEndpointConfig.Delete().Where(userinfoendpointconfig.HasServiceWith(service.ID(svc.ID))).Exec(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot delete user info endpoint configuration for service %s", name)
	}
	_, err = c.DB.EntClient.JwksEndpointConfig.Delete().Where(jwksendpointconfig.HasServiceWith(service.ID(svc.ID))).Exec(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot delete JWKS endpoint configuration for service %s", name)
	}
	_, err = c.DB.EntClient.WellKnownEndpointConfig.Delete().Where(wellknownendpointconfig.HasServiceWith(service.ID(svc.ID))).Exec(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot delete well known endpoint configuration for service %s", name)
	}
	_, err = c.DB.EntClient.LoginEndpointConfig.Delete().Where(loginendpointconfig.HasServiceWith(service.ID(svc.ID))).Exec(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot delete login endpoint configuration for service %s", name)
	}
	if err := c.deleteConnectionConfig(ctx, svc); err != nil {
		return errors.Wrapf(err, "cannot delete connection configuration for service %s", name)
	}

	err = c.DeleteKeySetByService(ctx, name)
	if err != nil {
		return errors.Wrapf(err, "cannot delete key sets for service %s", name)
	}

	if err := c.DB.EntClient.Service.DeleteOne(svc).Exec(ctx); err != nil {
		return errors.Wrapf(err, "cannot delete service %s", name)
	}
	return nil
}

// ListServices retrieves all services from the database.
func (c *Client) ListServices(ctx context.Context) ([]*ent.Service, error) {
	return c.DB.EntClient.Service.Query().All(ctx)
}

// UpdateService updates a service in the database.
func (c *Client) UpdateService(ctx context.Context, cfg config.Service) (*ent.Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, errors.Wrapf(err, "cannot create service %s - invalid configuration", cfg.Name)
	}

	current, err := c.GetService(ctx, cfg.Name)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get service %s", cfg.Name)
	}

	metadata, err := json.Marshal(cfg.ServiceMetadata)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to marshal metadata")
	}

	svc, err := c.DB.EntClient.Service.UpdateOne(current).
		SetName(cfg.Name).
		SetIssuer(cfg.Identifier).
		SetDescription(cfg.Description).
		SetServiceMetadata(string(metadata)).
		SetAllowedClientMetadata(cfg.AllowedClientMetadata).
		SetScopes(cfg.Scopes).
		SetGrantTypes(cfg.GrantTypes).
		SetResponseTypes(cfg.ResponseTypes).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot update service %s", cfg.Name)
	}

	// update the authorization endpoint
	authEndpointConfig, err := c.DB.EntClient.AuthorizationEndpointConfig.Query().Where(authorizationendpointconfig.HasServiceWith(service.ID(svc.ID))).Only(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get authorization endpoint config")
	}
	_, err = c.DB.EntClient.AuthorizationEndpointConfig.UpdateOne(authEndpointConfig).
		SetService(svc).
		SetEndpoint(cfg.AuthorizationEndpoint.Endpoint).
		SetPkceRequired(cfg.AuthorizationEndpoint.PKCERequired).
		SetPkceS256CodeChallengeMethodRequired(cfg.AuthorizationEndpoint.S256CodeChallengeMethodRequired).
		Save(ctx)

	// update the introspection endpoint
	introspectionEndpointConfig, err := c.DB.EntClient.IntrospectionEndpointConfig.Query().Where(introspectionendpointconfig.HasServiceWith(service.ID(svc.ID))).Only(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get introspection endpoint config")
	}
	_, err = c.DB.EntClient.IntrospectionEndpointConfig.UpdateOne(introspectionEndpointConfig).
		SetEndpoint(cfg.IntrospectionEndpoint.Endpoint).
		Save(ctx)

	// update the token endpoint
	tokenEndpointConfig, err := c.DB.EntClient.TokenEndpointConfig.Query().Where(tokenendpointconfig.HasServiceWith(service.ID(svc.ID))).Only(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get token endpoint config")
	}
	_, err = c.DB.EntClient.TokenEndpointConfig.UpdateOne(tokenEndpointConfig).
		SetEndpoint(cfg.TokenEndpoint.Endpoint).
		SetAllowedAuthenticationMethods(cfg.TokenEndpoint.AllowedAuthenticationMethods).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot update token endpoint configuration for service %s", cfg.Name)
	}

	// update the user info endpoint
	userInfoEndpointConfig, err := c.DB.EntClient.UserInfoEndpointConfig.Query().Where(userinfoendpointconfig.HasServiceWith(service.ID(svc.ID))).Only(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get user info endpoint config")
	}
	_, err = c.DB.EntClient.UserInfoEndpointConfig.UpdateOne(userInfoEndpointConfig).
		SetEndpoint(cfg.UserInfoEndpoint.Endpoint).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot update user info endpoint configuration for service %s", cfg.Name)
	}

	// update the JWKS endpoint
	jwksEndpointConfig, err := c.DB.EntClient.JwksEndpointConfig.Query().Where(jwksendpointconfig.HasServiceWith(service.ID(svc.ID))).Only(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get JWKS endpoint config")
	}
	_, err = c.DB.EntClient.JwksEndpointConfig.UpdateOne(jwksEndpointConfig).
		SetEndpoint(cfg.JWKSEndpoint.Endpoint).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot update JWKS endpoint configuration for service %s", cfg.Name)
	}

	// update the well known endpoint
	wellKnownEndpointConfig, err := c.DB.EntClient.WellKnownEndpointConfig.Query().Where(wellknownendpointconfig.HasServiceWith(service.ID(svc.ID))).Only(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get well known endpoint config")
	}
	_, err = c.DB.EntClient.WellKnownEndpointConfig.UpdateOne(wellKnownEndpointConfig).
		SetEndpoint(cfg.WellKnownEndpoint.Endpoint).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot update well known endpoint configuration for service %s", cfg.Name)
	}
	// update the login endpoint
	loginEndpointConfig, err := c.DB.EntClient.LoginEndpointConfig.Query().Where(loginendpointconfig.HasServiceWith(service.ID(svc.ID))).Only(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get login endpoint config")
	}
	_, err = c.DB.EntClient.LoginEndpointConfig.UpdateOne(loginEndpointConfig).
		SetEndpoint(cfg.LoginEndpoint.Endpoint).
		SetSessionTimeout(int64(cfg.LoginEndpoint.SessionTimeout)).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot update login endpoint configuration for service %s", cfg.Name)
	}
	_, err = c.updateConnectionConfigForService(ctx, svc, cfg.Connection)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot update connection configuration for service %s", cfg.Name)
	}

	if err := c.UpdateSigningKeysByService(ctx, cfg.Name, cfg.Keys); err != nil {
		return nil, errors.Wrapf(err, "cannot update signing keys for service %s", cfg.Name)
	}

	return svc, nil
}
