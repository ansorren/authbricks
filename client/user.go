package client

import (
	"context"
	"fmt"
	"golang.org/x/crypto/bcrypt"

	"go.authbricks.com/bricks/ent"
	"go.authbricks.com/bricks/ent/oidcconnection"

	"github.com/pkg/errors"
)

const (
	ConnectionTypeEmailPassword = "email_password"
	ConnectionTypeOIDC          = "oidc"
)

type CreateUserRequest struct {
	ConnectionType string
	UserID         string
	Username       string
	Password       string
	Service        *ent.Service
	ConnectionName string
}

// hashPassword hashes the given password using bcrypt.
func hashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", errors.Wrapf(err, "unable to generate bcrypt password hash")
	}
	return string(hashed), nil
}

// CreateUser creates a new user.
func (c *Client) CreateUser(ctx context.Context, request CreateUserRequest) (*ent.User, error) {
	// first figure out the connection
	switch request.ConnectionType {
	case ConnectionTypeEmailPassword:
		// get the email/password connection
		conn, err := request.Service.QueryServiceConnectionConfig().QueryEmailPasswordConnection().Only(ctx)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot find email/password connection for service %s", request.Service.Name)
		}

		hashed, err := hashPassword(request.Password)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot hash password for user %s", request.Username)
		}
		// create the user
		u, err := c.DB.EntClient.User.Create().
			SetID(request.UserID).
			SetUsername(request.Username).
			SetHashedPassword(hashed).
			SetNillableEmailPasswordConnectionID(&conn.ID).
			Save(ctx)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot create user %s", request.Username)
		}
		return u, nil
	case ConnectionTypeOIDC:
		// get the OIDC connection
		if request.ConnectionName == "" {
			return nil, errors.New("invalid request: the connection name is required for OIDC connections")
		}
		oidcConn, err := c.DB.EntClient.OIDCConnection.Query().Where(oidcconnection.ID(request.ConnectionName)).Only(ctx)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot find OIDC connection %s", request.ConnectionName)
		}
		// create the user
		u, err := c.DB.EntClient.User.Create().
			SetID(request.UserID).
			SetUsername(request.Username).
			SetHashedPassword(request.Password).
			SetNillableOidcConnectionsID(&oidcConn.ID).
			Save(ctx)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot create user %s", request.Username)
		}
		return u, nil
	default:
		return nil, fmt.Errorf("unknown connection type %s", request.ConnectionType)
	}
}

// GetUserByID retrieves the user with the given ID.
func (c *Client) GetUserByID(ctx context.Context, userID string) (*ent.User, error) {
	return c.DB.EntClient.User.Get(ctx, userID)
}

// UpdateUser updates the given user.
func (c *Client) UpdateUser(ctx context.Context, user *ent.User) (*ent.User, error) {
	updatedUser, err := c.DB.EntClient.User.UpdateOne(user).
		SetUsername(user.Username).
		SetHashedPassword(user.HashedPassword).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot update user %s", user.Username)
	}
	return updatedUser, nil
}

// DeleteUser deletes the given user.
func (c *Client) DeleteUser(ctx context.Context, user *ent.User) error {
	// delete the user
	err := c.DB.EntClient.User.DeleteOne(user).Exec(ctx)
	if err != nil {
		return errors.Wrapf(err, "cannot delete user %s", user.Username)
	}
	return nil
}
