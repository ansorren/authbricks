// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"go.authbricks.com/bricks/ent/emailpasswordconnection"
	"go.authbricks.com/bricks/ent/oidcconnection"
	"go.authbricks.com/bricks/ent/standardclaims"
	"go.authbricks.com/bricks/ent/user"
)

// User is the model entity for the User schema.
type User struct {
	config `json:"-"`
	// ID of the ent.
	ID string `json:"id"`
	// Username holds the value of the "username" field.
	Username string `json:"username"`
	// HashedPassword holds the value of the "hashed_password" field.
	HashedPassword string `json:"hashed_password"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the UserQuery when eager-loading is set.
	Edges                           UserEdges `json:"edges"`
	email_password_connection_users *string
	oidc_connection_users           *string
	selectValues                    sql.SelectValues
}

// UserEdges holds the relations/edges for other nodes in the graph.
type UserEdges struct {
	// StandardClaims holds the value of the standard_claims edge.
	StandardClaims *StandardClaims `json:"standard_claims,omitempty"`
	// EmailPasswordConnection holds the value of the email_password_connection edge.
	EmailPasswordConnection *EmailPasswordConnection `json:"email_password_connection,omitempty"`
	// OidcConnections holds the value of the oidc_connections edge.
	OidcConnections *OIDCConnection `json:"oidc_connections,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [3]bool
}

// StandardClaimsOrErr returns the StandardClaims value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e UserEdges) StandardClaimsOrErr() (*StandardClaims, error) {
	if e.StandardClaims != nil {
		return e.StandardClaims, nil
	} else if e.loadedTypes[0] {
		return nil, &NotFoundError{label: standardclaims.Label}
	}
	return nil, &NotLoadedError{edge: "standard_claims"}
}

// EmailPasswordConnectionOrErr returns the EmailPasswordConnection value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e UserEdges) EmailPasswordConnectionOrErr() (*EmailPasswordConnection, error) {
	if e.EmailPasswordConnection != nil {
		return e.EmailPasswordConnection, nil
	} else if e.loadedTypes[1] {
		return nil, &NotFoundError{label: emailpasswordconnection.Label}
	}
	return nil, &NotLoadedError{edge: "email_password_connection"}
}

// OidcConnectionsOrErr returns the OidcConnections value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e UserEdges) OidcConnectionsOrErr() (*OIDCConnection, error) {
	if e.OidcConnections != nil {
		return e.OidcConnections, nil
	} else if e.loadedTypes[2] {
		return nil, &NotFoundError{label: oidcconnection.Label}
	}
	return nil, &NotLoadedError{edge: "oidc_connections"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*User) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case user.FieldID, user.FieldUsername, user.FieldHashedPassword:
			values[i] = new(sql.NullString)
		case user.ForeignKeys[0]: // email_password_connection_users
			values[i] = new(sql.NullString)
		case user.ForeignKeys[1]: // oidc_connection_users
			values[i] = new(sql.NullString)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the User fields.
func (u *User) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case user.FieldID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value.Valid {
				u.ID = value.String
			}
		case user.FieldUsername:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field username", values[i])
			} else if value.Valid {
				u.Username = value.String
			}
		case user.FieldHashedPassword:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field hashed_password", values[i])
			} else if value.Valid {
				u.HashedPassword = value.String
			}
		case user.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field email_password_connection_users", values[i])
			} else if value.Valid {
				u.email_password_connection_users = new(string)
				*u.email_password_connection_users = value.String
			}
		case user.ForeignKeys[1]:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field oidc_connection_users", values[i])
			} else if value.Valid {
				u.oidc_connection_users = new(string)
				*u.oidc_connection_users = value.String
			}
		default:
			u.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the User.
// This includes values selected through modifiers, order, etc.
func (u *User) Value(name string) (ent.Value, error) {
	return u.selectValues.Get(name)
}

// QueryStandardClaims queries the "standard_claims" edge of the User entity.
func (u *User) QueryStandardClaims() *StandardClaimsQuery {
	return NewUserClient(u.config).QueryStandardClaims(u)
}

// QueryEmailPasswordConnection queries the "email_password_connection" edge of the User entity.
func (u *User) QueryEmailPasswordConnection() *EmailPasswordConnectionQuery {
	return NewUserClient(u.config).QueryEmailPasswordConnection(u)
}

// QueryOidcConnections queries the "oidc_connections" edge of the User entity.
func (u *User) QueryOidcConnections() *OIDCConnectionQuery {
	return NewUserClient(u.config).QueryOidcConnections(u)
}

// Update returns a builder for updating this User.
// Note that you need to call User.Unwrap() before calling this method if this User
// was returned from a transaction, and the transaction was committed or rolled back.
func (u *User) Update() *UserUpdateOne {
	return NewUserClient(u.config).UpdateOne(u)
}

// Unwrap unwraps the User entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (u *User) Unwrap() *User {
	_tx, ok := u.config.driver.(*txDriver)
	if !ok {
		panic("ent: User is not a transactional entity")
	}
	u.config.driver = _tx.drv
	return u
}

// String implements the fmt.Stringer.
func (u *User) String() string {
	var builder strings.Builder
	builder.WriteString("User(")
	builder.WriteString(fmt.Sprintf("id=%v, ", u.ID))
	builder.WriteString("username=")
	builder.WriteString(u.Username)
	builder.WriteString(", ")
	builder.WriteString("hashed_password=")
	builder.WriteString(u.HashedPassword)
	builder.WriteByte(')')
	return builder.String()
}

// Users is a parsable slice of User.
type Users []*User
