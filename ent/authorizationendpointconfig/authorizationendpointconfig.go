// Code generated by ent, DO NOT EDIT.

package authorizationendpointconfig

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
)

const (
	// Label holds the string label denoting the authorizationendpointconfig type in the database.
	Label = "authorization_endpoint_config"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldEndpoint holds the string denoting the endpoint field in the database.
	FieldEndpoint = "endpoint"
	// FieldPkceRequired holds the string denoting the pkce_required field in the database.
	FieldPkceRequired = "pkce_required"
	// FieldPkceS256CodeChallengeMethodRequired holds the string denoting the pkce_s256_code_challenge_method_required field in the database.
	FieldPkceS256CodeChallengeMethodRequired = "pkce_s256_code_challenge_method_required"
	// EdgeService holds the string denoting the service edge name in mutations.
	EdgeService = "service"
	// Table holds the table name of the authorizationendpointconfig in the database.
	Table = "authorization_endpoint_configs"
	// ServiceTable is the table that holds the service relation/edge.
	ServiceTable = "authorization_endpoint_configs"
	// ServiceInverseTable is the table name for the Service entity.
	// It exists in this package in order to avoid circular dependency with the "service" package.
	ServiceInverseTable = "services"
	// ServiceColumn is the table column denoting the service relation/edge.
	ServiceColumn = "service_service_authorization_endpoint_config"
)

// Columns holds all SQL columns for authorizationendpointconfig fields.
var Columns = []string{
	FieldID,
	FieldEndpoint,
	FieldPkceRequired,
	FieldPkceS256CodeChallengeMethodRequired,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "authorization_endpoint_configs"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"service_service_authorization_endpoint_config",
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

// OrderOption defines the ordering options for the AuthorizationEndpointConfig queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByEndpoint orders the results by the endpoint field.
func ByEndpoint(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldEndpoint, opts...).ToFunc()
}

// ByPkceRequired orders the results by the pkce_required field.
func ByPkceRequired(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldPkceRequired, opts...).ToFunc()
}

// ByPkceS256CodeChallengeMethodRequired orders the results by the pkce_s256_code_challenge_method_required field.
func ByPkceS256CodeChallengeMethodRequired(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldPkceS256CodeChallengeMethodRequired, opts...).ToFunc()
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