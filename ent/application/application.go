// Code generated by ent, DO NOT EDIT.

package application

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
)

const (
	// Label holds the string label denoting the application type in the database.
	Label = "application"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldName holds the string denoting the name field in the database.
	FieldName = "name"
	// FieldPublic holds the string denoting the public field in the database.
	FieldPublic = "public"
	// FieldDescription holds the string denoting the description field in the database.
	FieldDescription = "description"
	// FieldRedirectUris holds the string denoting the redirect_uris field in the database.
	FieldRedirectUris = "redirect_uris"
	// FieldResponseTypes holds the string denoting the response_types field in the database.
	FieldResponseTypes = "response_types"
	// FieldGrantTypes holds the string denoting the grant_types field in the database.
	FieldGrantTypes = "grant_types"
	// FieldScopes holds the string denoting the scopes field in the database.
	FieldScopes = "scopes"
	// FieldPKCERequired holds the string denoting the pkce_required field in the database.
	FieldPKCERequired = "pkce_required"
	// FieldS256CodeChallengeMethodRequired holds the string denoting the s256_code_challenge_method_required field in the database.
	FieldS256CodeChallengeMethodRequired = "s256_code_challenge_method_required"
	// FieldAllowedAuthenticationMethods holds the string denoting the allowed_authentication_methods field in the database.
	FieldAllowedAuthenticationMethods = "allowed_authentication_methods"
	// EdgeCredentials holds the string denoting the credentials edge name in mutations.
	EdgeCredentials = "credentials"
	// EdgeService holds the string denoting the service edge name in mutations.
	EdgeService = "service"
	// Table holds the table name of the application in the database.
	Table = "applications"
	// CredentialsTable is the table that holds the credentials relation/edge.
	CredentialsTable = "credentials"
	// CredentialsInverseTable is the table name for the Credentials entity.
	// It exists in this package in order to avoid circular dependency with the "credentials" package.
	CredentialsInverseTable = "credentials"
	// CredentialsColumn is the table column denoting the credentials relation/edge.
	CredentialsColumn = "application_credentials"
	// ServiceTable is the table that holds the service relation/edge.
	ServiceTable = "applications"
	// ServiceInverseTable is the table name for the Service entity.
	// It exists in this package in order to avoid circular dependency with the "service" package.
	ServiceInverseTable = "services"
	// ServiceColumn is the table column denoting the service relation/edge.
	ServiceColumn = "service_applications"
)

// Columns holds all SQL columns for application fields.
var Columns = []string{
	FieldID,
	FieldName,
	FieldPublic,
	FieldDescription,
	FieldRedirectUris,
	FieldResponseTypes,
	FieldGrantTypes,
	FieldScopes,
	FieldPKCERequired,
	FieldS256CodeChallengeMethodRequired,
	FieldAllowedAuthenticationMethods,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "applications"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"service_applications",
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
	// NameValidator is a validator for the "name" field. It is called by the builders before save.
	NameValidator func(string) error
	// DefaultPublic holds the default value on creation for the "public" field.
	DefaultPublic bool
	// DefaultPKCERequired holds the default value on creation for the "PKCE_required" field.
	DefaultPKCERequired bool
	// DefaultS256CodeChallengeMethodRequired holds the default value on creation for the "s256_code_challenge_method_required" field.
	DefaultS256CodeChallengeMethodRequired bool
	// IDValidator is a validator for the "id" field. It is called by the builders before save.
	IDValidator func(string) error
)

// OrderOption defines the ordering options for the Application queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByName orders the results by the name field.
func ByName(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldName, opts...).ToFunc()
}

// ByPublic orders the results by the public field.
func ByPublic(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldPublic, opts...).ToFunc()
}

// ByDescription orders the results by the description field.
func ByDescription(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldDescription, opts...).ToFunc()
}

// ByPKCERequired orders the results by the PKCE_required field.
func ByPKCERequired(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldPKCERequired, opts...).ToFunc()
}

// ByS256CodeChallengeMethodRequired orders the results by the s256_code_challenge_method_required field.
func ByS256CodeChallengeMethodRequired(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldS256CodeChallengeMethodRequired, opts...).ToFunc()
}

// ByCredentialsCount orders the results by credentials count.
func ByCredentialsCount(opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborsCount(s, newCredentialsStep(), opts...)
	}
}

// ByCredentials orders the results by credentials terms.
func ByCredentials(term sql.OrderTerm, terms ...sql.OrderTerm) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newCredentialsStep(), append([]sql.OrderTerm{term}, terms...)...)
	}
}

// ByServiceField orders the results by service field.
func ByServiceField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newServiceStep(), sql.OrderByField(field, opts...))
	}
}
func newCredentialsStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(CredentialsInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2M, false, CredentialsTable, CredentialsColumn),
	)
}
func newServiceStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(ServiceInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, true, ServiceTable, ServiceColumn),
	)
}
