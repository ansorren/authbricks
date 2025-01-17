package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Service holds the schema definition for the Service entity.
type Service struct {
	ent.Schema
}

// Fields of the Service.
func (Service) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id" hcl:"id"`),
		field.String("name").Unique().NotEmpty().StructTag(`json:"name" hcl:"name"`),
		field.String("issuer").Unique().NotEmpty().StructTag(`json:"issuer" hcl:"issuer"`),
		field.String("description").StructTag(`json:"description" hcl:"description"`),
		field.Strings("scopes").StructTag(`json:"scopes" hcl:"scopes"`),
		field.String("service_metadata").StructTag(`json:"service_metadata" hcl:"service_metadata"`),
		field.Strings("allowed_client_metadata").StructTag(`json:"allowed_client_metadata" hcl:"allowed_client_metadata"`),
		field.Strings("grant_types").StructTag(`json:"grant_types" hcl:"grant_types"`),
		field.Strings("response_types").StructTag(`json:"response_types" hcl:"response_types"`),
	}
}

// Edges of the Service.
func (Service) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("key_set", KeySet.Type).Unique(),
		edge.To("service_authorization_endpoint_config", AuthorizationEndpointConfig.Type).Unique(),
		edge.To("service_introspection_endpoint_config", IntrospectionEndpointConfig.Type).Unique(),
		edge.To("service_token_endpoint_config", TokenEndpointConfig.Type).Unique(),
		edge.To("service_user_info_endpoint_config", UserInfoEndpointConfig.Type).Unique(),
		edge.To("service_jwks_endpoint_config", JwksEndpointConfig.Type).Unique(),
		edge.To("service_well_known_endpoint_config", WellKnownEndpointConfig.Type).Unique(),
		edge.To("service_login_endpoint_config", LoginEndpointConfig.Type).Unique(),
		edge.To("service_connection_config", ConnectionConfig.Type).Unique(),
		edge.To("applications", Application.Type),
	}
}
