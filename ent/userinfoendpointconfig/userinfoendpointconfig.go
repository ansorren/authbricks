// Code generated by ent, DO NOT EDIT.

package userinfoendpointconfig

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
)

const (
	// Label holds the string label denoting the userinfoendpointconfig type in the database.
	Label = "user_info_endpoint_config"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldEndpoint holds the string denoting the endpoint field in the database.
	FieldEndpoint = "endpoint"
	// EdgeService holds the string denoting the service edge name in mutations.
	EdgeService = "service"
	// Table holds the table name of the userinfoendpointconfig in the database.
	Table = "user_info_endpoint_configs"
	// ServiceTable is the table that holds the service relation/edge.
	ServiceTable = "user_info_endpoint_configs"
	// ServiceInverseTable is the table name for the Service entity.
	// It exists in this package in order to avoid circular dependency with the "service" package.
	ServiceInverseTable = "services"
	// ServiceColumn is the table column denoting the service relation/edge.
	ServiceColumn = "service_service_user_info_endpoint_config"
)

// Columns holds all SQL columns for userinfoendpointconfig fields.
var Columns = []string{
	FieldID,
	FieldEndpoint,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "user_info_endpoint_configs"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"service_service_user_info_endpoint_config",
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	for i := range ForeignKeys {
		if column == ForeignKeys[i] {
			return true
		}
	}
	return false
}

var (
	// EndpointValidator is a validator for the "endpoint" field. It is called by the builders before save.
	EndpointValidator func(string) error
	// IDValidator is a validator for the "id" field. It is called by the builders before save.
	IDValidator func(string) error
)

// OrderOption defines the ordering options for the UserInfoEndpointConfig queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByEndpoint orders the results by the endpoint field.
func ByEndpoint(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldEndpoint, opts...).ToFunc()
}

// ByServiceField orders the results by service field.
func ByServiceField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newServiceStep(), sql.OrderByField(field, opts...))
	}
}
func newServiceStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(ServiceInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2O, true, ServiceTable, ServiceColumn),
	)
}
