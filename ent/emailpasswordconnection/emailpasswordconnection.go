// Code generated by ent, DO NOT EDIT.

package emailpasswordconnection

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
)

const (
	// Label holds the string label denoting the emailpasswordconnection type in the database.
	Label = "email_password_connection"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldEnabled holds the string denoting the enabled field in the database.
	FieldEnabled = "enabled"
	// EdgeConnectionConfig holds the string denoting the connection_config edge name in mutations.
	EdgeConnectionConfig = "connection_config"
	// EdgeUsers holds the string denoting the users edge name in mutations.
	EdgeUsers = "users"
	// Table holds the table name of the emailpasswordconnection in the database.
	Table = "email_password_connections"
	// ConnectionConfigTable is the table that holds the connection_config relation/edge.
	ConnectionConfigTable = "email_password_connections"
	// ConnectionConfigInverseTable is the table name for the ConnectionConfig entity.
	// It exists in this package in order to avoid circular dependency with the "connectionconfig" package.
	ConnectionConfigInverseTable = "connection_configs"
	// ConnectionConfigColumn is the table column denoting the connection_config relation/edge.
	ConnectionConfigColumn = "connection_config_email_password_connection"
	// UsersTable is the table that holds the users relation/edge.
	UsersTable = "users"
	// UsersInverseTable is the table name for the User entity.
	// It exists in this package in order to avoid circular dependency with the "user" package.
	UsersInverseTable = "users"
	// UsersColumn is the table column denoting the users relation/edge.
	UsersColumn = "email_password_connection_users"
)

// Columns holds all SQL columns for emailpasswordconnection fields.
var Columns = []string{
	FieldID,
	FieldEnabled,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "email_password_connections"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"connection_config_email_password_connection",
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
	// DefaultEnabled holds the default value on creation for the "enabled" field.
	DefaultEnabled bool
	// IDValidator is a validator for the "id" field. It is called by the builders before save.
	IDValidator func(string) error
)

// OrderOption defines the ordering options for the EmailPasswordConnection queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByEnabled orders the results by the enabled field.
func ByEnabled(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldEnabled, opts...).ToFunc()
}

// ByConnectionConfigField orders the results by connection_config field.
func ByConnectionConfigField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newConnectionConfigStep(), sql.OrderByField(field, opts...))
	}
}

// ByUsersField orders the results by users field.
func ByUsersField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newUsersStep(), sql.OrderByField(field, opts...))
	}
}
func newConnectionConfigStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(ConnectionConfigInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2O, true, ConnectionConfigTable, ConnectionConfigColumn),
	)
}
func newUsersStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(UsersInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2O, false, UsersTable, UsersColumn),
	)
}
