package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// ServiceAuthorizationEndpointConfig holds the schema definition for the ServiceAuthorizationEndpointConfig entity.
type ServiceAuthorizationEndpointConfig struct {
	ent.Schema
}

// Fields of the ServiceAuthorizationEndpointConfig.
func (ServiceAuthorizationEndpointConfig) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id" hcl:"id"`),
		field.String("endpoint").Unique().NotEmpty().StructTag(`json:"endpoint" hcl:"endpoint"`),
		field.Bool("pkce_required").StructTag(`json:"pkce_required" hcl:"pkce_required"`),
		field.Bool("pkce_s256_code_challenge_method_required").StructTag(`json:"pkce_s256_code_challenge_method" hcl:"pkce_s256_code_challenge_method"`),
	}
}

// Edges of the ServiceAuthorizationEndpointConfig.
func (ServiceAuthorizationEndpointConfig) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("service", Service.Type).Ref("service_authorization_endpoint_config").Unique().Required(),
	}
}
