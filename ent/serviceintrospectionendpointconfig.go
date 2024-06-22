// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"go.authbricks.com/bricks/ent/service"
	"go.authbricks.com/bricks/ent/serviceintrospectionendpointconfig"
)

// ServiceIntrospectionEndpointConfig is the model entity for the ServiceIntrospectionEndpointConfig schema.
type ServiceIntrospectionEndpointConfig struct {
	config `hcl:"-" json:"-"`
	// ID of the ent.
	ID string `json:"id" hcl:"id"`
	// Endpoint holds the value of the "endpoint" field.
	Endpoint string `json:"endpoint" hcl:"endpoint"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the ServiceIntrospectionEndpointConfigQuery when eager-loading is set.
	Edges                                         ServiceIntrospectionEndpointConfigEdges `json:"edges"`
	service_service_introspection_endpoint_config *string
	selectValues                                  sql.SelectValues
}

// ServiceIntrospectionEndpointConfigEdges holds the relations/edges for other nodes in the graph.
type ServiceIntrospectionEndpointConfigEdges struct {
	// Service holds the value of the service edge.
	Service *Service `json:"service,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
}

// ServiceOrErr returns the Service value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ServiceIntrospectionEndpointConfigEdges) ServiceOrErr() (*Service, error) {
	if e.Service != nil {
		return e.Service, nil
	} else if e.loadedTypes[0] {
		return nil, &NotFoundError{label: service.Label}
	}
	return nil, &NotLoadedError{edge: "service"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*ServiceIntrospectionEndpointConfig) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case serviceintrospectionendpointconfig.FieldID, serviceintrospectionendpointconfig.FieldEndpoint:
			values[i] = new(sql.NullString)
		case serviceintrospectionendpointconfig.ForeignKeys[0]: // service_service_introspection_endpoint_config
			values[i] = new(sql.NullString)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the ServiceIntrospectionEndpointConfig fields.
func (siec *ServiceIntrospectionEndpointConfig) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case serviceintrospectionendpointconfig.FieldID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value.Valid {
				siec.ID = value.String
			}
		case serviceintrospectionendpointconfig.FieldEndpoint:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field endpoint", values[i])
			} else if value.Valid {
				siec.Endpoint = value.String
			}
		case serviceintrospectionendpointconfig.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field service_service_introspection_endpoint_config", values[i])
			} else if value.Valid {
				siec.service_service_introspection_endpoint_config = new(string)
				*siec.service_service_introspection_endpoint_config = value.String
			}
		default:
			siec.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the ServiceIntrospectionEndpointConfig.
// This includes values selected through modifiers, order, etc.
func (siec *ServiceIntrospectionEndpointConfig) Value(name string) (ent.Value, error) {
	return siec.selectValues.Get(name)
}

// QueryService queries the "service" edge of the ServiceIntrospectionEndpointConfig entity.
func (siec *ServiceIntrospectionEndpointConfig) QueryService() *ServiceQuery {
	return NewServiceIntrospectionEndpointConfigClient(siec.config).QueryService(siec)
}

// Update returns a builder for updating this ServiceIntrospectionEndpointConfig.
// Note that you need to call ServiceIntrospectionEndpointConfig.Unwrap() before calling this method if this ServiceIntrospectionEndpointConfig
// was returned from a transaction, and the transaction was committed or rolled back.
func (siec *ServiceIntrospectionEndpointConfig) Update() *ServiceIntrospectionEndpointConfigUpdateOne {
	return NewServiceIntrospectionEndpointConfigClient(siec.config).UpdateOne(siec)
}

// Unwrap unwraps the ServiceIntrospectionEndpointConfig entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (siec *ServiceIntrospectionEndpointConfig) Unwrap() *ServiceIntrospectionEndpointConfig {
	_tx, ok := siec.config.driver.(*txDriver)
	if !ok {
		panic("ent: ServiceIntrospectionEndpointConfig is not a transactional entity")
	}
	siec.config.driver = _tx.drv
	return siec
}

// String implements the fmt.Stringer.
func (siec *ServiceIntrospectionEndpointConfig) String() string {
	var builder strings.Builder
	builder.WriteString("ServiceIntrospectionEndpointConfig(")
	builder.WriteString(fmt.Sprintf("id=%v, ", siec.ID))
	builder.WriteString("endpoint=")
	builder.WriteString(siec.Endpoint)
	builder.WriteByte(')')
	return builder.String()
}

// ServiceIntrospectionEndpointConfigs is a parsable slice of ServiceIntrospectionEndpointConfig.
type ServiceIntrospectionEndpointConfigs []*ServiceIntrospectionEndpointConfig
