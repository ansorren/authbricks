// Code generated by ent, DO NOT EDIT.

package migrate

import (
	"entgo.io/ent/dialect/sql/schema"
	"entgo.io/ent/schema/field"
)

var (
	// ApplicationsColumns holds the columns for the "applications" table.
	ApplicationsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "name", Type: field.TypeString, Unique: true},
		{Name: "public", Type: field.TypeBool, Default: false},
		{Name: "description", Type: field.TypeString},
		{Name: "redirect_uris", Type: field.TypeJSON},
		{Name: "response_types", Type: field.TypeJSON},
		{Name: "grant_types", Type: field.TypeJSON},
		{Name: "scopes", Type: field.TypeJSON},
		{Name: "pkce_required", Type: field.TypeBool, Default: false},
		{Name: "s256_code_challenge_method_required", Type: field.TypeBool, Default: false},
		{Name: "allowed_authentication_methods", Type: field.TypeJSON},
		{Name: "service_applications", Type: field.TypeString, Nullable: true},
	}
	// ApplicationsTable holds the schema information for the "applications" table.
	ApplicationsTable = &schema.Table{
		Name:       "applications",
		Columns:    ApplicationsColumns,
		PrimaryKey: []*schema.Column{ApplicationsColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "applications_services_applications",
				Columns:    []*schema.Column{ApplicationsColumns[11]},
				RefColumns: []*schema.Column{ServicesColumns[0]},
				OnDelete:   schema.SetNull,
			},
		},
	}
	// AuthorizationCodesColumns holds the columns for the "authorization_codes" table.
	AuthorizationCodesColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "application", Type: field.TypeString},
		{Name: "code_challenge", Type: field.TypeString},
		{Name: "code_challenge_method", Type: field.TypeString},
		{Name: "created_at", Type: field.TypeTime},
		{Name: "auth_time", Type: field.TypeTime},
		{Name: "redirect_uri", Type: field.TypeString},
		{Name: "nonce", Type: field.TypeString},
		{Name: "service", Type: field.TypeString},
		{Name: "state", Type: field.TypeString},
		{Name: "subject", Type: field.TypeString},
		{Name: "granted_scopes", Type: field.TypeString},
	}
	// AuthorizationCodesTable holds the schema information for the "authorization_codes" table.
	AuthorizationCodesTable = &schema.Table{
		Name:       "authorization_codes",
		Columns:    AuthorizationCodesColumns,
		PrimaryKey: []*schema.Column{AuthorizationCodesColumns[0]},
	}
	// AuthorizationEndpointConfigsColumns holds the columns for the "authorization_endpoint_configs" table.
	AuthorizationEndpointConfigsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "endpoint", Type: field.TypeString, Unique: true},
		{Name: "pkce_required", Type: field.TypeBool},
		{Name: "pkce_s256_code_challenge_method_required", Type: field.TypeBool},
		{Name: "service_service_authorization_endpoint_config", Type: field.TypeString, Unique: true},
	}
	// AuthorizationEndpointConfigsTable holds the schema information for the "authorization_endpoint_configs" table.
	AuthorizationEndpointConfigsTable = &schema.Table{
		Name:       "authorization_endpoint_configs",
		Columns:    AuthorizationEndpointConfigsColumns,
		PrimaryKey: []*schema.Column{AuthorizationEndpointConfigsColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "authorization_endpoint_configs_services_service_authorization_endpoint_config",
				Columns:    []*schema.Column{AuthorizationEndpointConfigsColumns[4]},
				RefColumns: []*schema.Column{ServicesColumns[0]},
				OnDelete:   schema.NoAction,
			},
		},
	}
	// AuthorizationPayloadsColumns holds the columns for the "authorization_payloads" table.
	AuthorizationPayloadsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "code_challenge", Type: field.TypeString},
		{Name: "code_challenge_method", Type: field.TypeString},
		{Name: "client_id", Type: field.TypeString},
		{Name: "nonce", Type: field.TypeString},
		{Name: "redirect_uri", Type: field.TypeString},
		{Name: "response_type", Type: field.TypeString},
		{Name: "scope", Type: field.TypeString},
		{Name: "service_name", Type: field.TypeString},
		{Name: "state", Type: field.TypeString},
		{Name: "response_mode", Type: field.TypeString},
		{Name: "session_authorization_payload", Type: field.TypeString, Unique: true, Nullable: true},
	}
	// AuthorizationPayloadsTable holds the schema information for the "authorization_payloads" table.
	AuthorizationPayloadsTable = &schema.Table{
		Name:       "authorization_payloads",
		Columns:    AuthorizationPayloadsColumns,
		PrimaryKey: []*schema.Column{AuthorizationPayloadsColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "authorization_payloads_sessions_authorization_payload",
				Columns:    []*schema.Column{AuthorizationPayloadsColumns[11]},
				RefColumns: []*schema.Column{SessionsColumns[0]},
				OnDelete:   schema.SetNull,
			},
		},
	}
	// ConnectionConfigsColumns holds the columns for the "connection_configs" table.
	ConnectionConfigsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "service_service_connection_config", Type: field.TypeString, Unique: true},
	}
	// ConnectionConfigsTable holds the schema information for the "connection_configs" table.
	ConnectionConfigsTable = &schema.Table{
		Name:       "connection_configs",
		Columns:    ConnectionConfigsColumns,
		PrimaryKey: []*schema.Column{ConnectionConfigsColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "connection_configs_services_service_connection_config",
				Columns:    []*schema.Column{ConnectionConfigsColumns[1]},
				RefColumns: []*schema.Column{ServicesColumns[0]},
				OnDelete:   schema.NoAction,
			},
		},
	}
	// CookieStoresColumns holds the columns for the "cookie_stores" table.
	CookieStoresColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "auth_key", Type: field.TypeString},
		{Name: "encryption_key", Type: field.TypeString},
	}
	// CookieStoresTable holds the schema information for the "cookie_stores" table.
	CookieStoresTable = &schema.Table{
		Name:       "cookie_stores",
		Columns:    CookieStoresColumns,
		PrimaryKey: []*schema.Column{CookieStoresColumns[0]},
	}
	// CredentialsColumns holds the columns for the "credentials" table.
	CredentialsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "client_id", Type: field.TypeString, Unique: true},
		{Name: "client_secret", Type: field.TypeString},
		{Name: "application_credentials", Type: field.TypeString, Nullable: true},
	}
	// CredentialsTable holds the schema information for the "credentials" table.
	CredentialsTable = &schema.Table{
		Name:       "credentials",
		Columns:    CredentialsColumns,
		PrimaryKey: []*schema.Column{CredentialsColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "credentials_applications_credentials",
				Columns:    []*schema.Column{CredentialsColumns[3]},
				RefColumns: []*schema.Column{ApplicationsColumns[0]},
				OnDelete:   schema.SetNull,
			},
		},
	}
	// EmailPasswordConnectionsColumns holds the columns for the "email_password_connections" table.
	EmailPasswordConnectionsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "enabled", Type: field.TypeBool, Default: false},
		{Name: "connection_config_email_password_connection", Type: field.TypeString, Unique: true},
	}
	// EmailPasswordConnectionsTable holds the schema information for the "email_password_connections" table.
	EmailPasswordConnectionsTable = &schema.Table{
		Name:       "email_password_connections",
		Columns:    EmailPasswordConnectionsColumns,
		PrimaryKey: []*schema.Column{EmailPasswordConnectionsColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "email_password_connections_connection_configs_email_password_connection",
				Columns:    []*schema.Column{EmailPasswordConnectionsColumns[2]},
				RefColumns: []*schema.Column{ConnectionConfigsColumns[0]},
				OnDelete:   schema.NoAction,
			},
		},
	}
	// IntrospectionEndpointConfigsColumns holds the columns for the "introspection_endpoint_configs" table.
	IntrospectionEndpointConfigsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "endpoint", Type: field.TypeString, Unique: true},
		{Name: "service_service_introspection_endpoint_config", Type: field.TypeString, Unique: true},
	}
	// IntrospectionEndpointConfigsTable holds the schema information for the "introspection_endpoint_configs" table.
	IntrospectionEndpointConfigsTable = &schema.Table{
		Name:       "introspection_endpoint_configs",
		Columns:    IntrospectionEndpointConfigsColumns,
		PrimaryKey: []*schema.Column{IntrospectionEndpointConfigsColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "introspection_endpoint_configs_services_service_introspection_endpoint_config",
				Columns:    []*schema.Column{IntrospectionEndpointConfigsColumns[2]},
				RefColumns: []*schema.Column{ServicesColumns[0]},
				OnDelete:   schema.NoAction,
			},
		},
	}
	// JwksEndpointConfigsColumns holds the columns for the "jwks_endpoint_configs" table.
	JwksEndpointConfigsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "endpoint", Type: field.TypeString, Unique: true},
		{Name: "service_service_jwks_endpoint_config", Type: field.TypeString, Unique: true},
	}
	// JwksEndpointConfigsTable holds the schema information for the "jwks_endpoint_configs" table.
	JwksEndpointConfigsTable = &schema.Table{
		Name:       "jwks_endpoint_configs",
		Columns:    JwksEndpointConfigsColumns,
		PrimaryKey: []*schema.Column{JwksEndpointConfigsColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "jwks_endpoint_configs_services_service_jwks_endpoint_config",
				Columns:    []*schema.Column{JwksEndpointConfigsColumns[2]},
				RefColumns: []*schema.Column{ServicesColumns[0]},
				OnDelete:   schema.NoAction,
			},
		},
	}
	// KeySetsColumns holds the columns for the "key_sets" table.
	KeySetsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "service_key_set", Type: field.TypeString, Unique: true, Nullable: true},
	}
	// KeySetsTable holds the schema information for the "key_sets" table.
	KeySetsTable = &schema.Table{
		Name:       "key_sets",
		Columns:    KeySetsColumns,
		PrimaryKey: []*schema.Column{KeySetsColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "key_sets_services_key_set",
				Columns:    []*schema.Column{KeySetsColumns[1]},
				RefColumns: []*schema.Column{ServicesColumns[0]},
				OnDelete:   schema.SetNull,
			},
		},
	}
	// LoginEndpointConfigsColumns holds the columns for the "login_endpoint_configs" table.
	LoginEndpointConfigsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "endpoint", Type: field.TypeString, Unique: true},
		{Name: "session_timeout", Type: field.TypeInt64},
		{Name: "service_service_login_endpoint_config", Type: field.TypeString, Unique: true},
	}
	// LoginEndpointConfigsTable holds the schema information for the "login_endpoint_configs" table.
	LoginEndpointConfigsTable = &schema.Table{
		Name:       "login_endpoint_configs",
		Columns:    LoginEndpointConfigsColumns,
		PrimaryKey: []*schema.Column{LoginEndpointConfigsColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "login_endpoint_configs_services_service_login_endpoint_config",
				Columns:    []*schema.Column{LoginEndpointConfigsColumns[3]},
				RefColumns: []*schema.Column{ServicesColumns[0]},
				OnDelete:   schema.NoAction,
			},
		},
	}
	// OidcConnectionsColumns holds the columns for the "oidc_connections" table.
	OidcConnectionsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "enabled", Type: field.TypeBool, Default: false},
		{Name: "client_id", Type: field.TypeString, Nullable: true},
		{Name: "client_secret", Type: field.TypeString, Nullable: true},
		{Name: "scopes", Type: field.TypeJSON, Nullable: true},
		{Name: "redirect_uri", Type: field.TypeString, Nullable: true},
		{Name: "well_known_openid_configuration", Type: field.TypeString, Nullable: true},
		{Name: "connection_config_oidc_connections", Type: field.TypeString, Nullable: true},
	}
	// OidcConnectionsTable holds the schema information for the "oidc_connections" table.
	OidcConnectionsTable = &schema.Table{
		Name:       "oidc_connections",
		Columns:    OidcConnectionsColumns,
		PrimaryKey: []*schema.Column{OidcConnectionsColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "oidc_connections_connection_configs_oidc_connections",
				Columns:    []*schema.Column{OidcConnectionsColumns[7]},
				RefColumns: []*schema.Column{ConnectionConfigsColumns[0]},
				OnDelete:   schema.SetNull,
			},
		},
	}
	// RefreshTokensColumns holds the columns for the "refresh_tokens" table.
	RefreshTokensColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "application", Type: field.TypeString},
		{Name: "service", Type: field.TypeString},
		{Name: "scopes", Type: field.TypeString},
		{Name: "created_at", Type: field.TypeInt64},
		{Name: "access_token_id", Type: field.TypeString},
		{Name: "lifetime", Type: field.TypeInt64},
		{Name: "subject", Type: field.TypeString},
		{Name: "key_id", Type: field.TypeString},
		{Name: "auth_time", Type: field.TypeTime},
	}
	// RefreshTokensTable holds the schema information for the "refresh_tokens" table.
	RefreshTokensTable = &schema.Table{
		Name:       "refresh_tokens",
		Columns:    RefreshTokensColumns,
		PrimaryKey: []*schema.Column{RefreshTokensColumns[0]},
		Indexes: []*schema.Index{
			{
				Name:    "refreshtoken_access_token_id",
				Unique:  true,
				Columns: []*schema.Column{RefreshTokensColumns[5]},
			},
		},
	}
	// ServicesColumns holds the columns for the "services" table.
	ServicesColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "name", Type: field.TypeString, Unique: true},
		{Name: "issuer", Type: field.TypeString, Unique: true},
		{Name: "description", Type: field.TypeString},
		{Name: "scopes", Type: field.TypeJSON},
		{Name: "service_metadata", Type: field.TypeString},
		{Name: "allowed_client_metadata", Type: field.TypeJSON},
		{Name: "grant_types", Type: field.TypeJSON},
		{Name: "response_types", Type: field.TypeJSON},
	}
	// ServicesTable holds the schema information for the "services" table.
	ServicesTable = &schema.Table{
		Name:       "services",
		Columns:    ServicesColumns,
		PrimaryKey: []*schema.Column{ServicesColumns[0]},
	}
	// SessionsColumns holds the columns for the "sessions" table.
	SessionsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "created_at", Type: field.TypeInt64},
		{Name: "service_name", Type: field.TypeString},
	}
	// SessionsTable holds the schema information for the "sessions" table.
	SessionsTable = &schema.Table{
		Name:       "sessions",
		Columns:    SessionsColumns,
		PrimaryKey: []*schema.Column{SessionsColumns[0]},
	}
	// SigningKeysColumns holds the columns for the "signing_keys" table.
	SigningKeysColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "key", Type: field.TypeString},
		{Name: "key_set_signing_keys", Type: field.TypeString, Nullable: true},
	}
	// SigningKeysTable holds the schema information for the "signing_keys" table.
	SigningKeysTable = &schema.Table{
		Name:       "signing_keys",
		Columns:    SigningKeysColumns,
		PrimaryKey: []*schema.Column{SigningKeysColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "signing_keys_key_sets_signing_keys",
				Columns:    []*schema.Column{SigningKeysColumns[2]},
				RefColumns: []*schema.Column{KeySetsColumns[0]},
				OnDelete:   schema.SetNull,
			},
		},
	}
	// StandardClaimsColumns holds the columns for the "standard_claims" table.
	StandardClaimsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "subject", Type: field.TypeString, Unique: true},
		{Name: "name", Type: field.TypeString, Nullable: true},
		{Name: "given_name", Type: field.TypeString, Nullable: true},
		{Name: "family_name", Type: field.TypeString, Nullable: true},
		{Name: "middle_name", Type: field.TypeString, Nullable: true},
		{Name: "nickname", Type: field.TypeString, Nullable: true},
		{Name: "preferred_username", Type: field.TypeString, Nullable: true},
		{Name: "profile", Type: field.TypeString, Nullable: true},
		{Name: "picture", Type: field.TypeString, Nullable: true},
		{Name: "website", Type: field.TypeString, Nullable: true},
		{Name: "email", Type: field.TypeString, Nullable: true},
		{Name: "email_verified", Type: field.TypeBool, Nullable: true, Default: false},
		{Name: "gender", Type: field.TypeString, Nullable: true},
		{Name: "birthdate", Type: field.TypeString, Nullable: true},
		{Name: "zoneinfo", Type: field.TypeString, Nullable: true},
		{Name: "locale", Type: field.TypeString, Nullable: true},
		{Name: "phone_number", Type: field.TypeString, Nullable: true},
		{Name: "phone_number_verified", Type: field.TypeBool, Nullable: true, Default: false},
		{Name: "address", Type: field.TypeString, Nullable: true},
		{Name: "updated_at", Type: field.TypeInt64, Nullable: true},
		{Name: "user_standard_claims", Type: field.TypeString, Unique: true},
	}
	// StandardClaimsTable holds the schema information for the "standard_claims" table.
	StandardClaimsTable = &schema.Table{
		Name:       "standard_claims",
		Columns:    StandardClaimsColumns,
		PrimaryKey: []*schema.Column{StandardClaimsColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "standard_claims_users_standard_claims",
				Columns:    []*schema.Column{StandardClaimsColumns[21]},
				RefColumns: []*schema.Column{UsersColumns[0]},
				OnDelete:   schema.NoAction,
			},
		},
	}
	// TokenEndpointConfigsColumns holds the columns for the "token_endpoint_configs" table.
	TokenEndpointConfigsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "endpoint", Type: field.TypeString, Unique: true},
		{Name: "allowed_authentication_methods", Type: field.TypeJSON},
		{Name: "service_service_token_endpoint_config", Type: field.TypeString, Unique: true},
	}
	// TokenEndpointConfigsTable holds the schema information for the "token_endpoint_configs" table.
	TokenEndpointConfigsTable = &schema.Table{
		Name:       "token_endpoint_configs",
		Columns:    TokenEndpointConfigsColumns,
		PrimaryKey: []*schema.Column{TokenEndpointConfigsColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "token_endpoint_configs_services_service_token_endpoint_config",
				Columns:    []*schema.Column{TokenEndpointConfigsColumns[3]},
				RefColumns: []*schema.Column{ServicesColumns[0]},
				OnDelete:   schema.NoAction,
			},
		},
	}
	// UsersColumns holds the columns for the "users" table.
	UsersColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "username", Type: field.TypeString},
		{Name: "hashed_password", Type: field.TypeString},
		{Name: "email_password_connection_users", Type: field.TypeString, Unique: true, Nullable: true},
		{Name: "oidc_connection_users", Type: field.TypeString, Unique: true, Nullable: true},
	}
	// UsersTable holds the schema information for the "users" table.
	UsersTable = &schema.Table{
		Name:       "users",
		Columns:    UsersColumns,
		PrimaryKey: []*schema.Column{UsersColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "users_email_password_connections_users",
				Columns:    []*schema.Column{UsersColumns[3]},
				RefColumns: []*schema.Column{EmailPasswordConnectionsColumns[0]},
				OnDelete:   schema.SetNull,
			},
			{
				Symbol:     "users_oidc_connections_users",
				Columns:    []*schema.Column{UsersColumns[4]},
				RefColumns: []*schema.Column{OidcConnectionsColumns[0]},
				OnDelete:   schema.SetNull,
			},
		},
	}
	// UserInfoEndpointConfigsColumns holds the columns for the "user_info_endpoint_configs" table.
	UserInfoEndpointConfigsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "endpoint", Type: field.TypeString, Unique: true},
		{Name: "service_service_user_info_endpoint_config", Type: field.TypeString, Unique: true},
	}
	// UserInfoEndpointConfigsTable holds the schema information for the "user_info_endpoint_configs" table.
	UserInfoEndpointConfigsTable = &schema.Table{
		Name:       "user_info_endpoint_configs",
		Columns:    UserInfoEndpointConfigsColumns,
		PrimaryKey: []*schema.Column{UserInfoEndpointConfigsColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "user_info_endpoint_configs_services_service_user_info_endpoint_config",
				Columns:    []*schema.Column{UserInfoEndpointConfigsColumns[2]},
				RefColumns: []*schema.Column{ServicesColumns[0]},
				OnDelete:   schema.NoAction,
			},
		},
	}
	// WellKnownEndpointConfigsColumns holds the columns for the "well_known_endpoint_configs" table.
	WellKnownEndpointConfigsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "endpoint", Type: field.TypeString, Unique: true},
		{Name: "service_service_well_known_endpoint_config", Type: field.TypeString, Unique: true},
	}
	// WellKnownEndpointConfigsTable holds the schema information for the "well_known_endpoint_configs" table.
	WellKnownEndpointConfigsTable = &schema.Table{
		Name:       "well_known_endpoint_configs",
		Columns:    WellKnownEndpointConfigsColumns,
		PrimaryKey: []*schema.Column{WellKnownEndpointConfigsColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "well_known_endpoint_configs_services_service_well_known_endpoint_config",
				Columns:    []*schema.Column{WellKnownEndpointConfigsColumns[2]},
				RefColumns: []*schema.Column{ServicesColumns[0]},
				OnDelete:   schema.NoAction,
			},
		},
	}
	// Tables holds all the tables in the schema.
	Tables = []*schema.Table{
		ApplicationsTable,
		AuthorizationCodesTable,
		AuthorizationEndpointConfigsTable,
		AuthorizationPayloadsTable,
		ConnectionConfigsTable,
		CookieStoresTable,
		CredentialsTable,
		EmailPasswordConnectionsTable,
		IntrospectionEndpointConfigsTable,
		JwksEndpointConfigsTable,
		KeySetsTable,
		LoginEndpointConfigsTable,
		OidcConnectionsTable,
		RefreshTokensTable,
		ServicesTable,
		SessionsTable,
		SigningKeysTable,
		StandardClaimsTable,
		TokenEndpointConfigsTable,
		UsersTable,
		UserInfoEndpointConfigsTable,
		WellKnownEndpointConfigsTable,
	}
)

func init() {
	ApplicationsTable.ForeignKeys[0].RefTable = ServicesTable
	AuthorizationEndpointConfigsTable.ForeignKeys[0].RefTable = ServicesTable
	AuthorizationPayloadsTable.ForeignKeys[0].RefTable = SessionsTable
	ConnectionConfigsTable.ForeignKeys[0].RefTable = ServicesTable
	CredentialsTable.ForeignKeys[0].RefTable = ApplicationsTable
	EmailPasswordConnectionsTable.ForeignKeys[0].RefTable = ConnectionConfigsTable
	IntrospectionEndpointConfigsTable.ForeignKeys[0].RefTable = ServicesTable
	JwksEndpointConfigsTable.ForeignKeys[0].RefTable = ServicesTable
	KeySetsTable.ForeignKeys[0].RefTable = ServicesTable
	LoginEndpointConfigsTable.ForeignKeys[0].RefTable = ServicesTable
	OidcConnectionsTable.ForeignKeys[0].RefTable = ConnectionConfigsTable
	SigningKeysTable.ForeignKeys[0].RefTable = KeySetsTable
	StandardClaimsTable.ForeignKeys[0].RefTable = UsersTable
	TokenEndpointConfigsTable.ForeignKeys[0].RefTable = ServicesTable
	UsersTable.ForeignKeys[0].RefTable = EmailPasswordConnectionsTable
	UsersTable.ForeignKeys[1].RefTable = OidcConnectionsTable
	UserInfoEndpointConfigsTable.ForeignKeys[0].RefTable = ServicesTable
	WellKnownEndpointConfigsTable.ForeignKeys[0].RefTable = ServicesTable
}
