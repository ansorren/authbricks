package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// TokenEndpointConfig holds the schema definition for the TokenEndpointConfig entity.
type TokenEndpointConfig struct {
	ent.Schema
}

// Fields of the TokenEndpointConfig.
func (TokenEndpointConfig) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id" hcl:"id"`),
		field.String("endpoint").Unique().NotEmpty().StructTag(`json:"endpoint" hcl:"endpoint"`),
		field.Strings("allowed_authentication_methods").StructTag(`json:"allowed_authentication_methods" hcl:"allowed_authentication_methods"`),
	}
}

// Edges of the TokenEndpointConfig.
func (TokenEndpointConfig) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("service", Service.Type).Ref("service_token_endpoint_config").Unique().Required(),
	}
}
