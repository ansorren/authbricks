// Code generated by ent, DO NOT EDIT.

package user

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
)

const (
	// Label holds the string label denoting the user type in the database.
	Label = "user"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldUsername holds the string denoting the username field in the database.
	FieldUsername = "username"
	// FieldPassword holds the string denoting the password field in the database.
	FieldPassword = "password"
	// EdgeUserPool holds the string denoting the user_pool edge name in mutations.
	EdgeUserPool = "user_pool"
	// EdgeStandardClaims holds the string denoting the standard_claims edge name in mutations.
	EdgeStandardClaims = "standard_claims"
	// Table holds the table name of the user in the database.
	Table = "users"
	// UserPoolTable is the table that holds the user_pool relation/edge.
	UserPoolTable = "users"
	// UserPoolInverseTable is the table name for the UserPool entity.
	// It exists in this package in order to avoid circular dependency with the "userpool" package.
	UserPoolInverseTable = "user_pools"
	// UserPoolColumn is the table column denoting the user_pool relation/edge.
	UserPoolColumn = "user_pool_users"
	// StandardClaimsTable is the table that holds the standard_claims relation/edge.
	StandardClaimsTable = "standard_claims"
	// StandardClaimsInverseTable is the table name for the StandardClaims entity.
	// It exists in this package in order to avoid circular dependency with the "standardclaims" package.
	StandardClaimsInverseTable = "standard_claims"
	// StandardClaimsColumn is the table column denoting the standard_claims relation/edge.
	StandardClaimsColumn = "user_standard_claims"
)

// Columns holds all SQL columns for user fields.
var Columns = []string{
	FieldID,
	FieldUsername,
	FieldPassword,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "users"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"user_pool_users",
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
	// UsernameValidator is a validator for the "username" field. It is called by the builders before save.
	UsernameValidator func(string) error
	// PasswordValidator is a validator for the "password" field. It is called by the builders before save.
	PasswordValidator func(string) error
	// IDValidator is a validator for the "id" field. It is called by the builders before save.
	IDValidator func(string) error
)

// OrderOption defines the ordering options for the User queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByUsername orders the results by the username field.
func ByUsername(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldUsername, opts...).ToFunc()
}

// ByPassword orders the results by the password field.
func ByPassword(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldPassword, opts...).ToFunc()
}

// ByUserPoolField orders the results by user_pool field.
func ByUserPoolField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newUserPoolStep(), sql.OrderByField(field, opts...))
	}
}

// ByStandardClaimsField orders the results by standard_claims field.
func ByStandardClaimsField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newStandardClaimsStep(), sql.OrderByField(field, opts...))
	}
}
func newUserPoolStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(UserPoolInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, true, UserPoolTable, UserPoolColumn),
	)
}
func newStandardClaimsStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(StandardClaimsInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2O, false, StandardClaimsTable, StandardClaimsColumn),
	)
}