package client

import (
	"context"
	"encoding/json"

	"go.authbricks.com/bricks/config"
	"go.authbricks.com/bricks/ent"
	"go.authbricks.com/bricks/ent/service"
	"go.authbricks.com/bricks/ent/serviceauthorizationendpointconfig"
	"go.authbricks.com/bricks/ent/serviceintrospectionendpointconfig"
	"go.authbricks.com/bricks/ent/servicetokenendpointconfig"
	"go.authbricks.com/bricks/ent/serviceuserinfoendpointconfig"

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
	_, err = c.DB.EntClient.ServiceAuthorizationEndpointConfig.Create().
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
	_, err = c.DB.EntClient.ServiceIntrospectionEndpointConfig.Create().
		SetID(uuid.New().String()).
		SetService(svc).
		SetEndpoint(cfg.IntrospectionEndpoint.Endpoint).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot create introspection endpoint configuration for service %s", cfg.Name)
	}

	// create the token endpoint
	_, err = c.DB.EntClient.ServiceTokenEndpointConfig.Create().
		SetID(uuid.New().String()).
		SetService(svc).
		SetEndpoint(cfg.TokenEndpoint.Endpoint).
		SetAllowedAuthenticationMethods(cfg.TokenEndpoint.AllowedAuthenticationMethods).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot create token endpoint configuration for service %s", cfg.Name)
	}

	// create the user info endpoint
	_, err = c.DB.EntClient.ServiceUserInfoEndpointConfig.Create().
		SetID(uuid.New().String()).
		SetService(svc).
		SetEndpoint(cfg.UserInfoEndpoint.Endpoint).
		Save(ctx)

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

	_, err = c.DB.EntClient.ServiceAuthorizationEndpointConfig.Delete().Where(serviceauthorizationendpointconfig.HasServiceWith(service.ID(svc.ID))).Exec(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot delete authorization endpoint configuration for service %s", name)
	}

	_, err = c.DB.EntClient.ServiceIntrospectionEndpointConfig.Delete().Where(serviceintrospectionendpointconfig.HasServiceWith(service.ID(svc.ID))).Exec(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot delete introspection endpoint configuration for service %s", name)
	}

	_, err = c.DB.EntClient.ServiceTokenEndpointConfig.Delete().Where(servicetokenendpointconfig.HasServiceWith(service.ID(svc.ID))).Exec(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot delete token endpoint configuration for service %s", name)
	}

	_, err = c.DB.EntClient.ServiceUserInfoEndpointConfig.Delete().Where(serviceuserinfoendpointconfig.HasServiceWith(service.ID(svc.ID))).Exec(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot delete user info endpoint configuration for service %s", name)
	}

	return c.DB.EntClient.Service.DeleteOne(svc).Exec(ctx)
}

// ListServices retrieves all services from the database.
func (c *Client) ListServices(ctx context.Context) ([]*ent.Service, error) {
	return c.DB.EntClient.Service.Query().All(ctx)
}

// UpdateService updates a service in the database.
func (c *Client) UpdateService(ctx context.Context, cfg config.Service) (*ent.Service, error) {
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
	authEndpointConfig, err := c.DB.EntClient.ServiceAuthorizationEndpointConfig.Query().Where(serviceauthorizationendpointconfig.HasServiceWith(service.ID(svc.ID))).Only(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get authorization endpoint config")
	}
	_, err = c.DB.EntClient.ServiceAuthorizationEndpointConfig.UpdateOne(authEndpointConfig).
		SetService(svc).
		SetEndpoint(cfg.AuthorizationEndpoint.Endpoint).
		SetPkceRequired(cfg.AuthorizationEndpoint.PKCERequired).
		SetPkceS256CodeChallengeMethodRequired(cfg.AuthorizationEndpoint.S256CodeChallengeMethodRequired).
		Save(ctx)

	// update the introspection endpoint
	introspectionEndpointConfig, err := c.DB.EntClient.ServiceIntrospectionEndpointConfig.Query().Where(serviceintrospectionendpointconfig.HasServiceWith(service.ID(svc.ID))).Only(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get introspection endpoint config")
	}
	_, err = c.DB.EntClient.ServiceIntrospectionEndpointConfig.UpdateOne(introspectionEndpointConfig).
		SetEndpoint(cfg.IntrospectionEndpoint.Endpoint).
		Save(ctx)

	// update the token endpoint
	tokenEndpointConfig, err := c.DB.EntClient.ServiceTokenEndpointConfig.Query().Where(servicetokenendpointconfig.HasServiceWith(service.ID(svc.ID))).Only(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get token endpoint config")
	}
	_, err = c.DB.EntClient.ServiceTokenEndpointConfig.UpdateOne(tokenEndpointConfig).
		SetEndpoint(cfg.TokenEndpoint.Endpoint).
		SetAllowedAuthenticationMethods(cfg.TokenEndpoint.AllowedAuthenticationMethods).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot update token endpoint configuration for service %s", cfg.Name)
	}

	// update the user info endpoint
	userInfoEndpointConfig, err := c.DB.EntClient.ServiceUserInfoEndpointConfig.Query().Where(serviceuserinfoendpointconfig.HasServiceWith(service.ID(svc.ID))).Only(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get user info endpoint config")
	}
	_, err = c.DB.EntClient.ServiceUserInfoEndpointConfig.UpdateOne(userInfoEndpointConfig).
		SetEndpoint(cfg.UserInfoEndpoint.Endpoint).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot update user info endpoint configuration for service %s", cfg.Name)
	}

	return svc, nil
}
