package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// JwksEndpointConfig holds the schema definition for the JwksEndpointConfig entity.
type JwksEndpointConfig struct {
	ent.Schema
}

// Fields of the JwksEndpointConfig.
func (JwksEndpointConfig) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id" hcl:"id"`),
		field.String("endpoint").Unique().NotEmpty().StructTag(`json:"endpoint" hcl:"endpoint"`),
	}
}

// Edges of the JwksEndpointConfig.
func (JwksEndpointConfig) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("service", Service.Type).Ref("service_jwks_endpoint_config").Unique().Required(),
	}
}
