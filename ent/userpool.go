// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"go.authbricks.com/bricks/ent/userpool"
)

// UserPool is the model entity for the UserPool schema.
type UserPool struct {
	config
	// ID of the ent.
	ID string `json:"id" hcl:"id"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the UserPoolQuery when eager-loading is set.
	Edges        UserPoolEdges `json:"edges"`
	selectValues sql.SelectValues
}

// UserPoolEdges holds the relations/edges for other nodes in the graph.
type UserPoolEdges struct {
	// Users holds the value of the users edge.
	Users []*User `json:"users,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
}

// UsersOrErr returns the Users value or an error if the edge
// was not loaded in eager-loading.
func (e UserPoolEdges) UsersOrErr() ([]*User, error) {
	if e.loadedTypes[0] {
		return e.Users, nil
	}
	return nil, &NotLoadedError{edge: "users"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*UserPool) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case userpool.FieldID:
			values[i] = new(sql.NullString)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the UserPool fields.
func (up *UserPool) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case userpool.FieldID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value.Valid {
				up.ID = value.String
			}
		default:
			up.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the UserPool.
// This includes values selected through modifiers, order, etc.
func (up *UserPool) Value(name string) (ent.Value, error) {
	return up.selectValues.Get(name)
}

// QueryUsers queries the "users" edge of the UserPool entity.
func (up *UserPool) QueryUsers() *UserQuery {
	return NewUserPoolClient(up.config).QueryUsers(up)
}

// Update returns a builder for updating this UserPool.
// Note that you need to call UserPool.Unwrap() before calling this method if this UserPool
// was returned from a transaction, and the transaction was committed or rolled back.
func (up *UserPool) Update() *UserPoolUpdateOne {
	return NewUserPoolClient(up.config).UpdateOne(up)
}

// Unwrap unwraps the UserPool entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (up *UserPool) Unwrap() *UserPool {
	_tx, ok := up.config.driver.(*txDriver)
	if !ok {
		panic("ent: UserPool is not a transactional entity")
	}
	up.config.driver = _tx.drv
	return up
}

// String implements the fmt.Stringer.
func (up *UserPool) String() string {
	var builder strings.Builder
	builder.WriteString("UserPool(")
	builder.WriteString(fmt.Sprintf("id=%v", up.ID))
	builder.WriteByte(')')
	return builder.String()
}

// UserPools is a parsable slice of UserPool.
type UserPools []*UserPool
