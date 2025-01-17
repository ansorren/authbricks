// Code generated by ent, DO NOT EDIT.

package ent

import (
	"encoding/json"
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"go.authbricks.com/bricks/ent/service"
	"go.authbricks.com/bricks/ent/tokenendpointconfig"
)

// TokenEndpointConfig is the model entity for the TokenEndpointConfig schema.
type TokenEndpointConfig struct {
	config `hcl:"-" json:"-"`
	// ID of the ent.
	ID string `json:"id" hcl:"id"`
	// Endpoint holds the value of the "endpoint" field.
	Endpoint string `json:"endpoint" hcl:"endpoint"`
	// AllowedAuthenticationMethods holds the value of the "allowed_authentication_methods" field.
	AllowedAuthenticationMethods []string `json:"allowed_authentication_methods" hcl:"allowed_authentication_methods"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the TokenEndpointConfigQuery when eager-loading is set.
	Edges                                 TokenEndpointConfigEdges `json:"edges"`
	service_service_token_endpoint_config *string
	selectValues                          sql.SelectValues
}

// TokenEndpointConfigEdges holds the relations/edges for other nodes in the graph.
type TokenEndpointConfigEdges struct {
	// Service holds the value of the service edge.
	Service *Service `json:"service,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
}

// ServiceOrErr returns the Service value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e TokenEndpointConfigEdges) ServiceOrErr() (*Service, error) {
	if e.Service != nil {
		return e.Service, nil
	} else if e.loadedTypes[0] {
		return nil, &NotFoundError{label: service.Label}
	}
	return nil, &NotLoadedError{edge: "service"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*TokenEndpointConfig) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case tokenendpointconfig.FieldAllowedAuthenticationMethods:
			values[i] = new([]byte)
		case tokenendpointconfig.FieldID, tokenendpointconfig.FieldEndpoint:
			values[i] = new(sql.NullString)
		case tokenendpointconfig.ForeignKeys[0]: // service_service_token_endpoint_config
			values[i] = new(sql.NullString)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the TokenEndpointConfig fields.
func (tec *TokenEndpointConfig) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case tokenendpointconfig.FieldID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value.Valid {
				tec.ID = value.String
			}
		case tokenendpointconfig.FieldEndpoint:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field endpoint", values[i])
			} else if value.Valid {
				tec.Endpoint = value.String
			}
		case tokenendpointconfig.FieldAllowedAuthenticationMethods:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field allowed_authentication_methods", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &tec.AllowedAuthenticationMethods); err != nil {
					return fmt.Errorf("unmarshal field allowed_authentication_methods: %w", err)
				}
			}
		case tokenendpointconfig.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field service_service_token_endpoint_config", values[i])
			} else if value.Valid {
				tec.service_service_token_endpoint_config = new(string)
				*tec.service_service_token_endpoint_config = value.String
			}
		default:
			tec.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the TokenEndpointConfig.
// This includes values selected through modifiers, order, etc.
func (tec *TokenEndpointConfig) Value(name string) (ent.Value, error) {
	return tec.selectValues.Get(name)
}

// QueryService queries the "service" edge of the TokenEndpointConfig entity.
func (tec *TokenEndpointConfig) QueryService() *ServiceQuery {
	return NewTokenEndpointConfigClient(tec.config).QueryService(tec)
}

// Update returns a builder for updating this TokenEndpointConfig.
// Note that you need to call TokenEndpointConfig.Unwrap() before calling this method if this TokenEndpointConfig
// was returned from a transaction, and the transaction was committed or rolled back.
func (tec *TokenEndpointConfig) Update() *TokenEndpointConfigUpdateOne {
	return NewTokenEndpointConfigClient(tec.config).UpdateOne(tec)
}

// Unwrap unwraps the TokenEndpointConfig entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (tec *TokenEndpointConfig) Unwrap() *TokenEndpointConfig {
	_tx, ok := tec.config.driver.(*txDriver)
	if !ok {
		panic("ent: TokenEndpointConfig is not a transactional entity")
	}
	tec.config.driver = _tx.drv
	return tec
}

// String implements the fmt.Stringer.
func (tec *TokenEndpointConfig) String() string {
	var builder strings.Builder
	builder.WriteString("TokenEndpointConfig(")
	builder.WriteString(fmt.Sprintf("id=%v, ", tec.ID))
	builder.WriteString("endpoint=")
	builder.WriteString(tec.Endpoint)
	builder.WriteString(", ")
	builder.WriteString("allowed_authentication_methods=")
	builder.WriteString(fmt.Sprintf("%v", tec.AllowedAuthenticationMethods))
	builder.WriteByte(')')
	return builder.String()
}

// TokenEndpointConfigs is a parsable slice of TokenEndpointConfig.
type TokenEndpointConfigs []*TokenEndpointConfig
