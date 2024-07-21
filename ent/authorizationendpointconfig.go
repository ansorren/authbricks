// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"go.authbricks.com/bricks/ent/authorizationendpointconfig"
	"go.authbricks.com/bricks/ent/service"
)

// AuthorizationEndpointConfig is the model entity for the AuthorizationEndpointConfig schema.
type AuthorizationEndpointConfig struct {
	config `hcl:"-" json:"-"`
	// ID of the ent.
	ID string `json:"id" hcl:"id"`
	// Endpoint holds the value of the "endpoint" field.
	Endpoint string `json:"endpoint" hcl:"endpoint"`
	// PkceRequired holds the value of the "pkce_required" field.
	PkceRequired bool `json:"pkce_required" hcl:"pkce_required"`
	// PkceS256CodeChallengeMethodRequired holds the value of the "pkce_s256_code_challenge_method_required" field.
	PkceS256CodeChallengeMethodRequired bool `json:"pkce_s256_code_challenge_method" hcl:"pkce_s256_code_challenge_method"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the AuthorizationEndpointConfigQuery when eager-loading is set.
	Edges                                         AuthorizationEndpointConfigEdges `json:"edges"`
	service_service_authorization_endpoint_config *string
	selectValues                                  sql.SelectValues
}

// AuthorizationEndpointConfigEdges holds the relations/edges for other nodes in the graph.
type AuthorizationEndpointConfigEdges struct {
	// Service holds the value of the service edge.
	Service *Service `json:"service,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
}

// ServiceOrErr returns the Service value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e AuthorizationEndpointConfigEdges) ServiceOrErr() (*Service, error) {
	if e.Service != nil {
		return e.Service, nil
	} else if e.loadedTypes[0] {
		return nil, &NotFoundError{label: service.Label}
	}
	return nil, &NotLoadedError{edge: "service"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*AuthorizationEndpointConfig) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case authorizationendpointconfig.FieldPkceRequired, authorizationendpointconfig.FieldPkceS256CodeChallengeMethodRequired:
			values[i] = new(sql.NullBool)
		case authorizationendpointconfig.FieldID, authorizationendpointconfig.FieldEndpoint:
			values[i] = new(sql.NullString)
		case authorizationendpointconfig.ForeignKeys[0]: // service_service_authorization_endpoint_config
			values[i] = new(sql.NullString)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the AuthorizationEndpointConfig fields.
func (aec *AuthorizationEndpointConfig) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case authorizationendpointconfig.FieldID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value.Valid {
				aec.ID = value.String
			}
		case authorizationendpointconfig.FieldEndpoint:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field endpoint", values[i])
			} else if value.Valid {
				aec.Endpoint = value.String
			}
		case authorizationendpointconfig.FieldPkceRequired:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field pkce_required", values[i])
			} else if value.Valid {
				aec.PkceRequired = value.Bool
			}
		case authorizationendpointconfig.FieldPkceS256CodeChallengeMethodRequired:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field pkce_s256_code_challenge_method_required", values[i])
			} else if value.Valid {
				aec.PkceS256CodeChallengeMethodRequired = value.Bool
			}
		case authorizationendpointconfig.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field service_service_authorization_endpoint_config", values[i])
			} else if value.Valid {
				aec.service_service_authorization_endpoint_config = new(string)
				*aec.service_service_authorization_endpoint_config = value.String
			}
		default:
			aec.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the AuthorizationEndpointConfig.
// This includes values selected through modifiers, order, etc.
func (aec *AuthorizationEndpointConfig) Value(name string) (ent.Value, error) {
	return aec.selectValues.Get(name)
}

// QueryService queries the "service" edge of the AuthorizationEndpointConfig entity.
func (aec *AuthorizationEndpointConfig) QueryService() *ServiceQuery {
	return NewAuthorizationEndpointConfigClient(aec.config).QueryService(aec)
}

// Update returns a builder for updating this AuthorizationEndpointConfig.
// Note that you need to call AuthorizationEndpointConfig.Unwrap() before calling this method if this AuthorizationEndpointConfig
// was returned from a transaction, and the transaction was committed or rolled back.
func (aec *AuthorizationEndpointConfig) Update() *AuthorizationEndpointConfigUpdateOne {
	return NewAuthorizationEndpointConfigClient(aec.config).UpdateOne(aec)
}

// Unwrap unwraps the AuthorizationEndpointConfig entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (aec *AuthorizationEndpointConfig) Unwrap() *AuthorizationEndpointConfig {
	_tx, ok := aec.config.driver.(*txDriver)
	if !ok {
		panic("ent: AuthorizationEndpointConfig is not a transactional entity")
	}
	aec.config.driver = _tx.drv
	return aec
}

// String implements the fmt.Stringer.
func (aec *AuthorizationEndpointConfig) String() string {
	var builder strings.Builder
	builder.WriteString("AuthorizationEndpointConfig(")
	builder.WriteString(fmt.Sprintf("id=%v, ", aec.ID))
	builder.WriteString("endpoint=")
	builder.WriteString(aec.Endpoint)
	builder.WriteString(", ")
	builder.WriteString("pkce_required=")
	builder.WriteString(fmt.Sprintf("%v", aec.PkceRequired))
	builder.WriteString(", ")
	builder.WriteString("pkce_s256_code_challenge_method_required=")
	builder.WriteString(fmt.Sprintf("%v", aec.PkceS256CodeChallengeMethodRequired))
	builder.WriteByte(')')
	return builder.String()
}

// AuthorizationEndpointConfigs is a parsable slice of AuthorizationEndpointConfig.
type AuthorizationEndpointConfigs []*AuthorizationEndpointConfig