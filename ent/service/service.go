// Code generated by ent, DO NOT EDIT.

package service

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
)

const (
	// Label holds the string label denoting the service type in the database.
	Label = "service"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldName holds the string denoting the name field in the database.
	FieldName = "name"
	// FieldIssuer holds the string denoting the issuer field in the database.
	FieldIssuer = "issuer"
	// FieldDescription holds the string denoting the description field in the database.
	FieldDescription = "description"
	// FieldScopes holds the string denoting the scopes field in the database.
	FieldScopes = "scopes"
	// FieldServiceMetadata holds the string denoting the service_metadata field in the database.
	FieldServiceMetadata = "service_metadata"
	// FieldAllowedClientMetadata holds the string denoting the allowed_client_metadata field in the database.
	FieldAllowedClientMetadata = "allowed_client_metadata"
	// FieldGrantTypes holds the string denoting the grant_types field in the database.
	FieldGrantTypes = "grant_types"
	// FieldResponseTypes holds the string denoting the response_types field in the database.
	FieldResponseTypes = "response_types"
	// EdgeKeySet holds the string denoting the key_set edge name in mutations.
	EdgeKeySet = "key_set"
	// EdgeServiceAuthorizationEndpointConfig holds the string denoting the service_authorization_endpoint_config edge name in mutations.
	EdgeServiceAuthorizationEndpointConfig = "service_authorization_endpoint_config"
	// EdgeServiceIntrospectionEndpointConfig holds the string denoting the service_introspection_endpoint_config edge name in mutations.
	EdgeServiceIntrospectionEndpointConfig = "service_introspection_endpoint_config"
	// EdgeServiceTokenEndpointConfig holds the string denoting the service_token_endpoint_config edge name in mutations.
	EdgeServiceTokenEndpointConfig = "service_token_endpoint_config"
	// EdgeServiceUserInfoEndpointConfig holds the string denoting the service_user_info_endpoint_config edge name in mutations.
	EdgeServiceUserInfoEndpointConfig = "service_user_info_endpoint_config"
	// EdgeServiceJwksEndpointConfig holds the string denoting the service_jwks_endpoint_config edge name in mutations.
	EdgeServiceJwksEndpointConfig = "service_jwks_endpoint_config"
	// EdgeServiceWellKnownEndpointConfig holds the string denoting the service_well_known_endpoint_config edge name in mutations.
	EdgeServiceWellKnownEndpointConfig = "service_well_known_endpoint_config"
	// EdgeServiceLoginEndpointConfig holds the string denoting the service_login_endpoint_config edge name in mutations.
	EdgeServiceLoginEndpointConfig = "service_login_endpoint_config"
	// EdgeServiceConnectionConfig holds the string denoting the service_connection_config edge name in mutations.
	EdgeServiceConnectionConfig = "service_connection_config"
	// EdgeApplications holds the string denoting the applications edge name in mutations.
	EdgeApplications = "applications"
	// Table holds the table name of the service in the database.
	Table = "services"
	// KeySetTable is the table that holds the key_set relation/edge.
	KeySetTable = "key_sets"
	// KeySetInverseTable is the table name for the KeySet entity.
	// It exists in this package in order to avoid circular dependency with the "keyset" package.
	KeySetInverseTable = "key_sets"
	// KeySetColumn is the table column denoting the key_set relation/edge.
	KeySetColumn = "service_key_set"
	// ServiceAuthorizationEndpointConfigTable is the table that holds the service_authorization_endpoint_config relation/edge.
	ServiceAuthorizationEndpointConfigTable = "authorization_endpoint_configs"
	// ServiceAuthorizationEndpointConfigInverseTable is the table name for the AuthorizationEndpointConfig entity.
	// It exists in this package in order to avoid circular dependency with the "authorizationendpointconfig" package.
	ServiceAuthorizationEndpointConfigInverseTable = "authorization_endpoint_configs"
	// ServiceAuthorizationEndpointConfigColumn is the table column denoting the service_authorization_endpoint_config relation/edge.
	ServiceAuthorizationEndpointConfigColumn = "service_service_authorization_endpoint_config"
	// ServiceIntrospectionEndpointConfigTable is the table that holds the service_introspection_endpoint_config relation/edge.
	ServiceIntrospectionEndpointConfigTable = "introspection_endpoint_configs"
	// ServiceIntrospectionEndpointConfigInverseTable is the table name for the IntrospectionEndpointConfig entity.
	// It exists in this package in order to avoid circular dependency with the "introspectionendpointconfig" package.
	ServiceIntrospectionEndpointConfigInverseTable = "introspection_endpoint_configs"
	// ServiceIntrospectionEndpointConfigColumn is the table column denoting the service_introspection_endpoint_config relation/edge.
	ServiceIntrospectionEndpointConfigColumn = "service_service_introspection_endpoint_config"
	// ServiceTokenEndpointConfigTable is the table that holds the service_token_endpoint_config relation/edge.
	ServiceTokenEndpointConfigTable = "token_endpoint_configs"
	// ServiceTokenEndpointConfigInverseTable is the table name for the TokenEndpointConfig entity.
	// It exists in this package in order to avoid circular dependency with the "tokenendpointconfig" package.
	ServiceTokenEndpointConfigInverseTable = "token_endpoint_configs"
	// ServiceTokenEndpointConfigColumn is the table column denoting the service_token_endpoint_config relation/edge.
	ServiceTokenEndpointConfigColumn = "service_service_token_endpoint_config"
	// ServiceUserInfoEndpointConfigTable is the table that holds the service_user_info_endpoint_config relation/edge.
	ServiceUserInfoEndpointConfigTable = "user_info_endpoint_configs"
	// ServiceUserInfoEndpointConfigInverseTable is the table name for the UserInfoEndpointConfig entity.
	// It exists in this package in order to avoid circular dependency with the "userinfoendpointconfig" package.
	ServiceUserInfoEndpointConfigInverseTable = "user_info_endpoint_configs"
	// ServiceUserInfoEndpointConfigColumn is the table column denoting the service_user_info_endpoint_config relation/edge.
	ServiceUserInfoEndpointConfigColumn = "service_service_user_info_endpoint_config"
	// ServiceJwksEndpointConfigTable is the table that holds the service_jwks_endpoint_config relation/edge.
	ServiceJwksEndpointConfigTable = "jwks_endpoint_configs"
	// ServiceJwksEndpointConfigInverseTable is the table name for the JwksEndpointConfig entity.
	// It exists in this package in order to avoid circular dependency with the "jwksendpointconfig" package.
	ServiceJwksEndpointConfigInverseTable = "jwks_endpoint_configs"
	// ServiceJwksEndpointConfigColumn is the table column denoting the service_jwks_endpoint_config relation/edge.
	ServiceJwksEndpointConfigColumn = "service_service_jwks_endpoint_config"
	// ServiceWellKnownEndpointConfigTable is the table that holds the service_well_known_endpoint_config relation/edge.
	ServiceWellKnownEndpointConfigTable = "well_known_endpoint_configs"
	// ServiceWellKnownEndpointConfigInverseTable is the table name for the WellKnownEndpointConfig entity.
	// It exists in this package in order to avoid circular dependency with the "wellknownendpointconfig" package.
	ServiceWellKnownEndpointConfigInverseTable = "well_known_endpoint_configs"
	// ServiceWellKnownEndpointConfigColumn is the table column denoting the service_well_known_endpoint_config relation/edge.
	ServiceWellKnownEndpointConfigColumn = "service_service_well_known_endpoint_config"
	// ServiceLoginEndpointConfigTable is the table that holds the service_login_endpoint_config relation/edge.
	ServiceLoginEndpointConfigTable = "login_endpoint_configs"
	// ServiceLoginEndpointConfigInverseTable is the table name for the LoginEndpointConfig entity.
	// It exists in this package in order to avoid circular dependency with the "loginendpointconfig" package.
	ServiceLoginEndpointConfigInverseTable = "login_endpoint_configs"
	// ServiceLoginEndpointConfigColumn is the table column denoting the service_login_endpoint_config relation/edge.
	ServiceLoginEndpointConfigColumn = "service_service_login_endpoint_config"
	// ServiceConnectionConfigTable is the table that holds the service_connection_config relation/edge.
	ServiceConnectionConfigTable = "connection_configs"
	// ServiceConnectionConfigInverseTable is the table name for the ConnectionConfig entity.
	// It exists in this package in order to avoid circular dependency with the "connectionconfig" package.
	ServiceConnectionConfigInverseTable = "connection_configs"
	// ServiceConnectionConfigColumn is the table column denoting the service_connection_config relation/edge.
	ServiceConnectionConfigColumn = "service_service_connection_config"
	// ApplicationsTable is the table that holds the applications relation/edge.
	ApplicationsTable = "applications"
	// ApplicationsInverseTable is the table name for the Application entity.
	// It exists in this package in order to avoid circular dependency with the "application" package.
	ApplicationsInverseTable = "applications"
	// ApplicationsColumn is the table column denoting the applications relation/edge.
	ApplicationsColumn = "service_applications"
)

// Columns holds all SQL columns for service fields.
var Columns = []string{
	FieldID,
	FieldName,
	FieldIssuer,
	FieldDescription,
	FieldScopes,
	FieldServiceMetadata,
	FieldAllowedClientMetadata,
	FieldGrantTypes,
	FieldResponseTypes,
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
	// NameValidator is a validator for the "name" field. It is called by the builders before save.
	NameValidator func(string) error
	// IssuerValidator is a validator for the "issuer" field. It is called by the builders before save.
	IssuerValidator func(string) error
	// IDValidator is a validator for the "id" field. It is called by the builders before save.
	IDValidator func(string) error
)

// OrderOption defines the ordering options for the Service queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByName orders the results by the name field.
func ByName(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldName, opts...).ToFunc()
}

// ByIssuer orders the results by the issuer field.
func ByIssuer(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldIssuer, opts...).ToFunc()
}

// ByDescription orders the results by the description field.
func ByDescription(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldDescription, opts...).ToFunc()
}

// ByServiceMetadata orders the results by the service_metadata field.
func ByServiceMetadata(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldServiceMetadata, opts...).ToFunc()
}

// ByKeySetField orders the results by key_set field.
func ByKeySetField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newKeySetStep(), sql.OrderByField(field, opts...))
	}
}

// ByServiceAuthorizationEndpointConfigField orders the results by service_authorization_endpoint_config field.
func ByServiceAuthorizationEndpointConfigField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newServiceAuthorizationEndpointConfigStep(), sql.OrderByField(field, opts...))
	}
}

// ByServiceIntrospectionEndpointConfigField orders the results by service_introspection_endpoint_config field.
func ByServiceIntrospectionEndpointConfigField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newServiceIntrospectionEndpointConfigStep(), sql.OrderByField(field, opts...))
	}
}

// ByServiceTokenEndpointConfigField orders the results by service_token_endpoint_config field.
func ByServiceTokenEndpointConfigField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newServiceTokenEndpointConfigStep(), sql.OrderByField(field, opts...))
	}
}

// ByServiceUserInfoEndpointConfigField orders the results by service_user_info_endpoint_config field.
func ByServiceUserInfoEndpointConfigField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newServiceUserInfoEndpointConfigStep(), sql.OrderByField(field, opts...))
	}
}

// ByServiceJwksEndpointConfigField orders the results by service_jwks_endpoint_config field.
func ByServiceJwksEndpointConfigField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newServiceJwksEndpointConfigStep(), sql.OrderByField(field, opts...))
	}
}

// ByServiceWellKnownEndpointConfigField orders the results by service_well_known_endpoint_config field.
func ByServiceWellKnownEndpointConfigField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newServiceWellKnownEndpointConfigStep(), sql.OrderByField(field, opts...))
	}
}

// ByServiceLoginEndpointConfigField orders the results by service_login_endpoint_config field.
func ByServiceLoginEndpointConfigField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newServiceLoginEndpointConfigStep(), sql.OrderByField(field, opts...))
	}
}

// ByServiceConnectionConfigField orders the results by service_connection_config field.
func ByServiceConnectionConfigField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newServiceConnectionConfigStep(), sql.OrderByField(field, opts...))
	}
}

// ByApplicationsCount orders the results by applications count.
func ByApplicationsCount(opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborsCount(s, newApplicationsStep(), opts...)
	}
}

// ByApplications orders the results by applications terms.
func ByApplications(term sql.OrderTerm, terms ...sql.OrderTerm) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newApplicationsStep(), append([]sql.OrderTerm{term}, terms...)...)
	}
}
func newKeySetStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(KeySetInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2O, false, KeySetTable, KeySetColumn),
	)
}
func newServiceAuthorizationEndpointConfigStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(ServiceAuthorizationEndpointConfigInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2O, false, ServiceAuthorizationEndpointConfigTable, ServiceAuthorizationEndpointConfigColumn),
	)
}
func newServiceIntrospectionEndpointConfigStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(ServiceIntrospectionEndpointConfigInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2O, false, ServiceIntrospectionEndpointConfigTable, ServiceIntrospectionEndpointConfigColumn),
	)
}
func newServiceTokenEndpointConfigStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(ServiceTokenEndpointConfigInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2O, false, ServiceTokenEndpointConfigTable, ServiceTokenEndpointConfigColumn),
	)
}
func newServiceUserInfoEndpointConfigStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(ServiceUserInfoEndpointConfigInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2O, false, ServiceUserInfoEndpointConfigTable, ServiceUserInfoEndpointConfigColumn),
	)
}
func newServiceJwksEndpointConfigStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(ServiceJwksEndpointConfigInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2O, false, ServiceJwksEndpointConfigTable, ServiceJwksEndpointConfigColumn),
	)
}
func newServiceWellKnownEndpointConfigStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(ServiceWellKnownEndpointConfigInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2O, false, ServiceWellKnownEndpointConfigTable, ServiceWellKnownEndpointConfigColumn),
	)
}
func newServiceLoginEndpointConfigStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(ServiceLoginEndpointConfigInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2O, false, ServiceLoginEndpointConfigTable, ServiceLoginEndpointConfigColumn),
	)
}
func newServiceConnectionConfigStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(ServiceConnectionConfigInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2O, false, ServiceConnectionConfigTable, ServiceConnectionConfigColumn),
	)
}
func newApplicationsStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(ApplicationsInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.O2M, false, ApplicationsTable, ApplicationsColumn),
	)
}
