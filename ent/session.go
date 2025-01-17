// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"go.authbricks.com/bricks/ent/authorizationpayload"
	"go.authbricks.com/bricks/ent/session"
)

// Session is the model entity for the Session schema.
type Session struct {
	config `json:"-"`
	// ID of the ent.
	ID string `json:"id"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt int64 `json:"created_at"`
	// ServiceName holds the value of the "service_name" field.
	ServiceName string `json:"service_name"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the SessionQuery when eager-loading is set.
	Edges        SessionEdges `json:"edges"`
	selectValues sql.SelectValues
}

// SessionEdges holds the relations/edges for other nodes in the graph.
type SessionEdges struct {
	// AuthorizationPayload holds the value of the authorization_payload edge.
	AuthorizationPayload *AuthorizationPayload `json:"authorization_payload,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
}

// AuthorizationPayloadOrErr returns the AuthorizationPayload value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e SessionEdges) AuthorizationPayloadOrErr() (*AuthorizationPayload, error) {
	if e.AuthorizationPayload != nil {
		return e.AuthorizationPayload, nil
	} else if e.loadedTypes[0] {
		return nil, &NotFoundError{label: authorizationpayload.Label}
	}
	return nil, &NotLoadedError{edge: "authorization_payload"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Session) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case session.FieldCreatedAt:
			values[i] = new(sql.NullInt64)
		case session.FieldID, session.FieldServiceName:
			values[i] = new(sql.NullString)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Session fields.
func (s *Session) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case session.FieldID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value.Valid {
				s.ID = value.String
			}
		case session.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				s.CreatedAt = value.Int64
			}
		case session.FieldServiceName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field service_name", values[i])
			} else if value.Valid {
				s.ServiceName = value.String
			}
		default:
			s.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the Session.
// This includes values selected through modifiers, order, etc.
func (s *Session) Value(name string) (ent.Value, error) {
	return s.selectValues.Get(name)
}

// QueryAuthorizationPayload queries the "authorization_payload" edge of the Session entity.
func (s *Session) QueryAuthorizationPayload() *AuthorizationPayloadQuery {
	return NewSessionClient(s.config).QueryAuthorizationPayload(s)
}

// Update returns a builder for updating this Session.
// Note that you need to call Session.Unwrap() before calling this method if this Session
// was returned from a transaction, and the transaction was committed or rolled back.
func (s *Session) Update() *SessionUpdateOne {
	return NewSessionClient(s.config).UpdateOne(s)
}

// Unwrap unwraps the Session entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (s *Session) Unwrap() *Session {
	_tx, ok := s.config.driver.(*txDriver)
	if !ok {
		panic("ent: Session is not a transactional entity")
	}
	s.config.driver = _tx.drv
	return s
}

// String implements the fmt.Stringer.
func (s *Session) String() string {
	var builder strings.Builder
	builder.WriteString("Session(")
	builder.WriteString(fmt.Sprintf("id=%v, ", s.ID))
	builder.WriteString("created_at=")
	builder.WriteString(fmt.Sprintf("%v", s.CreatedAt))
	builder.WriteString(", ")
	builder.WriteString("service_name=")
	builder.WriteString(s.ServiceName)
	builder.WriteByte(')')
	return builder.String()
}

// Sessions is a parsable slice of Session.
type Sessions []*Session
