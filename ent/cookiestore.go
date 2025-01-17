// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"go.authbricks.com/bricks/ent/cookiestore"
)

// CookieStore is the model entity for the CookieStore schema.
type CookieStore struct {
	config `json:"-"`
	// ID of the ent.
	ID string `json:"id"`
	// AuthKey holds the value of the "auth_key" field.
	AuthKey string `json:"auth_key"`
	// EncryptionKey holds the value of the "encryption_key" field.
	EncryptionKey string `json:"encryption_key"`
	selectValues  sql.SelectValues
}

// scanValues returns the types for scanning values from sql.Rows.
func (*CookieStore) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case cookiestore.FieldID, cookiestore.FieldAuthKey, cookiestore.FieldEncryptionKey:
			values[i] = new(sql.NullString)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the CookieStore fields.
func (cs *CookieStore) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case cookiestore.FieldID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value.Valid {
				cs.ID = value.String
			}
		case cookiestore.FieldAuthKey:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field auth_key", values[i])
			} else if value.Valid {
				cs.AuthKey = value.String
			}
		case cookiestore.FieldEncryptionKey:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field encryption_key", values[i])
			} else if value.Valid {
				cs.EncryptionKey = value.String
			}
		default:
			cs.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the CookieStore.
// This includes values selected through modifiers, order, etc.
func (cs *CookieStore) Value(name string) (ent.Value, error) {
	return cs.selectValues.Get(name)
}

// Update returns a builder for updating this CookieStore.
// Note that you need to call CookieStore.Unwrap() before calling this method if this CookieStore
// was returned from a transaction, and the transaction was committed or rolled back.
func (cs *CookieStore) Update() *CookieStoreUpdateOne {
	return NewCookieStoreClient(cs.config).UpdateOne(cs)
}

// Unwrap unwraps the CookieStore entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (cs *CookieStore) Unwrap() *CookieStore {
	_tx, ok := cs.config.driver.(*txDriver)
	if !ok {
		panic("ent: CookieStore is not a transactional entity")
	}
	cs.config.driver = _tx.drv
	return cs
}

// String implements the fmt.Stringer.
func (cs *CookieStore) String() string {
	var builder strings.Builder
	builder.WriteString("CookieStore(")
	builder.WriteString(fmt.Sprintf("id=%v, ", cs.ID))
	builder.WriteString("auth_key=")
	builder.WriteString(cs.AuthKey)
	builder.WriteString(", ")
	builder.WriteString("encryption_key=")
	builder.WriteString(cs.EncryptionKey)
	builder.WriteByte(')')
	return builder.String()
}

// CookieStores is a parsable slice of CookieStore.
type CookieStores []*CookieStore
