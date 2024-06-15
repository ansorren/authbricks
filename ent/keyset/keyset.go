// Code generated by ent, DO NOT EDIT.

package keyset

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
)

const (
	// Label holds the string label denoting the keyset type in the database.
	Label = "key_set"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// EdgeOauthServer holds the string denoting the oauth_server edge name in mutations.
	EdgeOauthServer = "oauth_server"
	// EdgeSigningKeys holds the string denoting the signing_keys edge name in mutations.
	EdgeSigningKeys = "signing_keys"
	// Table holds the table name of the keyset in the database.
	Table = "key_sets"
	// OauthServerTable is the table that holds the oauth_server relation/edge.
	OauthServerTable = "key_sets"
	// OauthServerInverseTable is the table name for the OAuthServer entity.
	// It exists in this package in order to avoid circular dependency with the "oauthserver" package.
	OauthServerInverseTable = "oauth_servers"
	// OauthServerColumn is the table column denoting the oauth_server relation/edge.
	OauthServerColumn = "oauth_server_key_set"
	// SigningKeysTable is the table that holds the signing_keys relation/edge.
	SigningKeysTable = "signing_keys"
	// SigningKeysInverseTable is the table name for the SigningKey entity.
	// It exists in this package in order to avoid circular dependency with the "signingkey" package.
	SigningKeysInverseTable = "signing_keys"
	// SigningKeysColumn is the table column denoting the signing_keys relation/edge.
	SigningKeysColumn = "key_set_signing_keys"
)

// Columns holds all SQL columns for keyset fields.
var Columns = []string{
	FieldID,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "key_sets"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"oauth_server_key_set",
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
	// IDValidator is a validator for the "id" field. It is called by the builders before save.
	IDValidator func(string) error
)

// OrderOption defines the ordering options for the KeySet queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByOauthServerField orders the results by oauth_server field.
func ByOauthServerField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newOauthServerStep(), sql.OrderByField(field, opts...))
	}
}

// BySigningKeysCount orders the results by signing_keys count.
func BySigningKeysCount(opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborsCount(s, newSigningKeysStep(), opts...)
	}
}

// BySigningKeys orders the results by signing_keys terms.
func BySigningKeys(term sql.OrderTerm, terms ...sql.OrderTerm) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newSigningKeysStep(), append([]sql.OrderTerm{term}, terms...)...)
	}
}
func newOauthServerStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(OauthServerInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2O, true, OauthServerTable, OauthServerColumn),
	)
}
func newSigningKeysStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(SigningKeysInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2M, false, SigningKeysTable, SigningKeysColumn),
	)
}
