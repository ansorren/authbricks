// Code generated by ent, DO NOT EDIT.

package session

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
)

const (
	// Label holds the string label denoting the session type in the database.
	Label = "session"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldCreatedAt holds the string denoting the created_at field in the database.
	FieldCreatedAt = "created_at"
	// FieldServiceName holds the string denoting the service_name field in the database.
	FieldServiceName = "service_name"
	// EdgeAuthorizationPayload holds the string denoting the authorization_payload edge name in mutations.
	EdgeAuthorizationPayload = "authorization_payload"
	// Table holds the table name of the session in the database.
	Table = "sessions"
	// AuthorizationPayloadTable is the table that holds the authorization_payload relation/edge.
	AuthorizationPayloadTable = "authorization_payloads"
	// AuthorizationPayloadInverseTable is the table name for the AuthorizationPayload entity.
	// It exists in this package in order to avoid circular dependency with the "authorizationpayload" package.
	AuthorizationPayloadInverseTable = "authorization_payloads"
	// AuthorizationPayloadColumn is the table column denoting the authorization_payload relation/edge.
	AuthorizationPayloadColumn = "session_authorization_payload"
)

// Columns holds all SQL columns for session fields.
var Columns = []string{
	FieldID,
	FieldCreatedAt,
	FieldServiceName,
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	return false
}

var (
	// CreatedAtValidator is a validator for the "created_at" field. It is called by the builders before save.
	CreatedAtValidator func(int64) error
	// ServiceNameValidator is a validator for the "service_name" field. It is called by the builders before save.
	ServiceNameValidator func(string) error
	// IDValidator is a validator for the "id" field. It is called by the builders before save.
	IDValidator func(string) error
)

// OrderOption defines the ordering options for the Session queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByCreatedAt orders the results by the created_at field.
func ByCreatedAt(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldCreatedAt, opts...).ToFunc()
}

// ByServiceName orders the results by the service_name field.
func ByServiceName(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldServiceName, opts...).ToFunc()
}

// ByAuthorizationPayloadField orders the results by authorization_payload field.
func ByAuthorizationPayloadField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newAuthorizationPayloadStep(), sql.OrderByField(field, opts...))
	}
}
func newAuthorizationPayloadStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(AuthorizationPayloadInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2O, false, AuthorizationPayloadTable, AuthorizationPayloadColumn),
	)
}
