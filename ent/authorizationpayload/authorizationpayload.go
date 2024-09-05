// Code generated by ent, DO NOT EDIT.

package authorizationpayload

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
)

const (
	// Label holds the string label denoting the authorizationpayload type in the database.
	Label = "authorization_payload"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldCodeChallenge holds the string denoting the code_challenge field in the database.
	FieldCodeChallenge = "code_challenge"
	// FieldCodeChallengeMethod holds the string denoting the code_challenge_method field in the database.
	FieldCodeChallengeMethod = "code_challenge_method"
	// FieldClientID holds the string denoting the client_id field in the database.
	FieldClientID = "client_id"
	// FieldNonce holds the string denoting the nonce field in the database.
	FieldNonce = "nonce"
	// FieldRedirectURI holds the string denoting the redirect_uri field in the database.
	FieldRedirectURI = "redirect_uri"
	// FieldResponseType holds the string denoting the response_type field in the database.
	FieldResponseType = "response_type"
	// FieldScope holds the string denoting the scope field in the database.
	FieldScope = "scope"
	// FieldServiceName holds the string denoting the service_name field in the database.
	FieldServiceName = "service_name"
	// FieldState holds the string denoting the state field in the database.
	FieldState = "state"
	// FieldResponseMode holds the string denoting the response_mode field in the database.
	FieldResponseMode = "response_mode"
	// EdgeSession holds the string denoting the session edge name in mutations.
	EdgeSession = "session"
	// Table holds the table name of the authorizationpayload in the database.
	Table = "authorization_payloads"
	// SessionTable is the table that holds the session relation/edge.
	SessionTable = "authorization_payloads"
	// SessionInverseTable is the table name for the Session entity.
	// It exists in this package in order to avoid circular dependency with the "session" package.
	SessionInverseTable = "sessions"
	// SessionColumn is the table column denoting the session relation/edge.
	SessionColumn = "session_authorization_payload"
)

// Columns holds all SQL columns for authorizationpayload fields.
var Columns = []string{
	FieldID,
	FieldCodeChallenge,
	FieldCodeChallengeMethod,
	FieldClientID,
	FieldNonce,
	FieldRedirectURI,
	FieldResponseType,
	FieldScope,
	FieldServiceName,
	FieldState,
	FieldResponseMode,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "authorization_payloads"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"session_authorization_payload",
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

// OrderOption defines the ordering options for the AuthorizationPayload queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByCodeChallenge orders the results by the code_challenge field.
func ByCodeChallenge(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldCodeChallenge, opts...).ToFunc()
}

// ByCodeChallengeMethod orders the results by the code_challenge_method field.
func ByCodeChallengeMethod(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldCodeChallengeMethod, opts...).ToFunc()
}

// ByClientID orders the results by the client_id field.
func ByClientID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldClientID, opts...).ToFunc()
}

// ByNonce orders the results by the nonce field.
func ByNonce(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldNonce, opts...).ToFunc()
}

// ByRedirectURI orders the results by the redirect_uri field.
func ByRedirectURI(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldRedirectURI, opts...).ToFunc()
}

// ByResponseType orders the results by the response_type field.
func ByResponseType(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldResponseType, opts...).ToFunc()
}

// ByScope orders the results by the scope field.
func ByScope(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldScope, opts...).ToFunc()
}

// ByServiceName orders the results by the service_name field.
func ByServiceName(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldServiceName, opts...).ToFunc()
}

// ByState orders the results by the state field.
func ByState(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldState, opts...).ToFunc()
}

// ByResponseMode orders the results by the response_mode field.
func ByResponseMode(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldResponseMode, opts...).ToFunc()
}

// BySessionField orders the results by session field.
func BySessionField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newSessionStep(), sql.OrderByField(field, opts...))
	}
}
func newSessionStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(SessionInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2O, true, SessionTable, SessionColumn),
	)
}
