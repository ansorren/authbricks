package api

import (
	"context"
	"go.authbricks.com/bricks/ent/user"
	"golang.org/x/crypto/bcrypt"
	"io"
	"time"

	"go.authbricks.com/bricks/ent"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

const (
	connectorIDEmailPassword   = "email_password"
	connectorTypeEmailPassword = "email_password"
	connectorTypeOIDC          = "oidc"
)

// Connector is the interface that must be implemented by the concrete types
// to handle the authentication logic.
type Connector interface {
	ID() string
	Connect(echo.Context, *ent.Service, io.Reader) (UserContext, error)
	Type() string
}

// EmailPasswordConnector is a connector for email/password authentication.
type EmailPasswordConnector struct{}

// EmailPasswordPayload is the payload for the email/password connector.
type EmailPasswordPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Connect handles the authentication logic for the email/password connector.
func (e *EmailPasswordConnector) Connect(c echo.Context, service *ent.Service, body io.Reader) (UserContext, error) {
	unmarshaler := NewUnmarshaler[EmailPasswordPayload](body)
	payload, err := unmarshaler.Unmarshal()
	if err != nil {
		return UserContext{}, errors.Wrap(err, "unable to unmarshal email/password payload")
	}

	connConfig, err := service.QueryServiceConnectionConfig().Only(c.Request().Context())
	if err != nil {
		return UserContext{}, errors.Wrap(err, "unable to get service connection config")
	}

	emailPassConn, err := connConfig.QueryEmailPasswordConnection().Only(c.Request().Context())
	if err != nil {
		return UserContext{}, errors.Wrap(err, "unable to get email password connection")
	}

	u, err := emailPassConn.QueryUsers().Where(user.Username(payload.Username)).Only(c.Request().Context())
	switch {
	case ent.IsNotFound(err):
		return UserContext{}, errors.New("user not found")
	case err != nil:
		return UserContext{}, errors.Wrap(err, "unable to get user")
	default:
	}
	err = bcrypt.CompareHashAndPassword([]byte(u.HashedPassword), []byte(payload.Password))
	if err != nil {
		return UserContext{}, errors.Wrap(err, "invalid password")
	}

	return UserContext{
		Authenticated: true,
		Subject:       Subject(u.ID),
		ServiceName:   service.Name,
		authTime:      time.Now(),
	}, nil

}

// Type returns the type of the connector.
func (e *EmailPasswordConnector) Type() string {
	return connectorTypeEmailPassword
}

func (e *EmailPasswordConnector) ID() string {
	return connectorIDEmailPassword
}

type Connectors []Connector

func (connectors Connectors) EmailPassword() Connector {
	for _, conn := range connectors {
		if conn.Type() == connectorTypeEmailPassword {
			return conn
		}
	}
	return nil
}

func (connectors Connectors) OIDC(connectionName string) Connector {
	for _, conn := range connectors {
		if conn.Type() == connectorTypeOIDC && conn.ID() == connectionName {
			return conn
		}
	}
	return nil
}

// OIDCConnector is a connector for the OIDC authentication.
type OIDCConnector struct {
	Name              string
	ClientID          string
	ClientSecret      string
	RedirectURI       string
	Scopes            []string
	WellKnownEndpoint string
}

func (o *OIDCConnector) ID() string {
	return o.Name
}

// Connect handles the authentication logic for the OIDC connector.
func (o *OIDCConnector) Connect(_ echo.Context, _ *ent.Service, _ io.Reader) (UserContext, error) {
	return UserContext{}, errors.New("not implemented")
}

// Type returns the type of the connector.
func (o *OIDCConnector) Type() string {
	return connectorTypeOIDC
}

// getAvailableConnectors retrieves the available connectors for the given service.
func (a *API) getAvailableConnectors(ctx context.Context, service *ent.Service) ([]Connector, error) {
	var ret []Connector

	connectionConfig, err := service.QueryServiceConnectionConfig().Only(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get service connection config")
	}

	emailPass, err := connectionConfig.QueryEmailPasswordConnection().Only(ctx)
	switch {
	case ent.IsNotFound(err):
		// do nothing
	case err != nil:
		return nil, errors.Wrap(err, "unable to get email password connection")
	default:
		if emailPass.Enabled {
			ret = append(ret, &EmailPasswordConnector{})
		}
	}
	oidcConnections, err := connectionConfig.QueryOidcConnections().All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get oidc connections")
	}
	for _, oidcConn := range oidcConnections {
		if oidcConn.Enabled {
			ret = append(ret, &OIDCConnector{
				Name:         oidcConn.ID,
				ClientID:     oidcConn.ClientID,
				ClientSecret: oidcConn.ClientSecret,
				RedirectURI:  oidcConn.RedirectURI,
				Scopes:       oidcConn.Scopes,
			})
		}
	}
	return ret, nil
}
