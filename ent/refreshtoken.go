// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"go.authbricks.com/bricks/ent/refreshtoken"
)

// RefreshToken is the model entity for the RefreshToken schema.
type RefreshToken struct {
	config `json:"-"`
	// ID of the ent.
	ID string `json:"id"`
	// Application holds the value of the "application" field.
	Application string `json:"application"`
	// Service holds the value of the "service" field.
	Service string `json:"service"`
	// Scopes holds the value of the "scopes" field.
	Scopes string `json:"scopes"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt int64 `json:"created_at"`
	// AccessTokenID holds the value of the "access_token_id" field.
	AccessTokenID string `json:"access_token_id"`
	// Lifetime holds the value of the "lifetime" field.
	Lifetime int64 `json:"lifetime"`
	// Subject holds the value of the "subject" field.
	Subject string `json:"subject"`
	// KeyID holds the value of the "key_id" field.
	KeyID string `json:"key_id"`
	// AuthTime holds the value of the "auth_time" field.
	AuthTime     time.Time `json:"auth_time"`
	selectValues sql.SelectValues
}

// scanValues returns the types for scanning values from sql.Rows.
func (*RefreshToken) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case refreshtoken.FieldCreatedAt, refreshtoken.FieldLifetime:
			values[i] = new(sql.NullInt64)
		case refreshtoken.FieldID, refreshtoken.FieldApplication, refreshtoken.FieldService, refreshtoken.FieldScopes, refreshtoken.FieldAccessTokenID, refreshtoken.FieldSubject, refreshtoken.FieldKeyID:
			values[i] = new(sql.NullString)
		case refreshtoken.FieldAuthTime:
			values[i] = new(sql.NullTime)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the RefreshToken fields.
func (rt *RefreshToken) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case refreshtoken.FieldID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value.Valid {
				rt.ID = value.String
			}
		case refreshtoken.FieldApplication:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field application", values[i])
			} else if value.Valid {
				rt.Application = value.String
			}
		case refreshtoken.FieldService:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field service", values[i])
			} else if value.Valid {
				rt.Service = value.String
			}
		case refreshtoken.FieldScopes:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field scopes", values[i])
			} else if value.Valid {
				rt.Scopes = value.String
			}
		case refreshtoken.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				rt.CreatedAt = value.Int64
			}
		case refreshtoken.FieldAccessTokenID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field access_token_id", values[i])
			} else if value.Valid {
				rt.AccessTokenID = value.String
			}
		case refreshtoken.FieldLifetime:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field lifetime", values[i])
			} else if value.Valid {
				rt.Lifetime = value.Int64
			}
		case refreshtoken.FieldSubject:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field subject", values[i])
			} else if value.Valid {
				rt.Subject = value.String
			}
		case refreshtoken.FieldKeyID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field key_id", values[i])
			} else if value.Valid {
				rt.KeyID = value.String
			}
		case refreshtoken.FieldAuthTime:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field auth_time", values[i])
			} else if value.Valid {
				rt.AuthTime = value.Time
			}
		default:
			rt.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the RefreshToken.
// This includes values selected through modifiers, order, etc.
func (rt *RefreshToken) Value(name string) (ent.Value, error) {
	return rt.selectValues.Get(name)
}

// Update returns a builder for updating this RefreshToken.
// Note that you need to call RefreshToken.Unwrap() before calling this method if this RefreshToken
// was returned from a transaction, and the transaction was committed or rolled back.
func (rt *RefreshToken) Update() *RefreshTokenUpdateOne {
	return NewRefreshTokenClient(rt.config).UpdateOne(rt)
}

// Unwrap unwraps the RefreshToken entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (rt *RefreshToken) Unwrap() *RefreshToken {
	_tx, ok := rt.config.driver.(*txDriver)
	if !ok {
		panic("ent: RefreshToken is not a transactional entity")
	}
	rt.config.driver = _tx.drv
	return rt
}

// String implements the fmt.Stringer.
func (rt *RefreshToken) String() string {
	var builder strings.Builder
	builder.WriteString("RefreshToken(")
	builder.WriteString(fmt.Sprintf("id=%v, ", rt.ID))
	builder.WriteString("application=")
	builder.WriteString(rt.Application)
	builder.WriteString(", ")
	builder.WriteString("service=")
	builder.WriteString(rt.Service)
	builder.WriteString(", ")
	builder.WriteString("scopes=")
	builder.WriteString(rt.Scopes)
	builder.WriteString(", ")
	builder.WriteString("created_at=")
	builder.WriteString(fmt.Sprintf("%v", rt.CreatedAt))
	builder.WriteString(", ")
	builder.WriteString("access_token_id=")
	builder.WriteString(rt.AccessTokenID)
	builder.WriteString(", ")
	builder.WriteString("lifetime=")
	builder.WriteString(fmt.Sprintf("%v", rt.Lifetime))
	builder.WriteString(", ")
	builder.WriteString("subject=")
	builder.WriteString(rt.Subject)
	builder.WriteString(", ")
	builder.WriteString("key_id=")
	builder.WriteString(rt.KeyID)
	builder.WriteString(", ")
	builder.WriteString("auth_time=")
	builder.WriteString(rt.AuthTime.Format(time.ANSIC))
	builder.WriteByte(')')
	return builder.String()
}

// RefreshTokens is a parsable slice of RefreshToken.
type RefreshTokens []*RefreshToken
