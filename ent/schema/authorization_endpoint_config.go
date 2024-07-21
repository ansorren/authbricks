package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// AuthorizationEndpointConfig holds the schema definition for the AuthorizationEndpointConfig entity.
type AuthorizationEndpointConfig struct {
	ent.Schema
}

// Fields of the AuthorizationEndpointConfig.
func (AuthorizationEndpointConfig) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id" hcl:"id"`),
		field.String("endpoint").Unique().NotEmpty().StructTag(`json:"endpoint" hcl:"endpoint"`),
		field.Bool("pkce_required").StructTag(`json:"pkce_required" hcl:"pkce_required"`),
		field.Bool("pkce_s256_code_challenge_method_required").StructTag(`json:"pkce_s256_code_challenge_method" hcl:"pkce_s256_code_challenge_method"`),
	}
}

// Edges of the AuthorizationEndpointConfig.
func (AuthorizationEndpointConfig) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("service", Service.Type).Ref("service_authorization_endpoint_config").Unique().Required(),
	}
}
