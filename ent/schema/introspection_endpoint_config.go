package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// IntrospectionEndpointConfig holds the schema definition for the IntrospectionEndpointConfig entity.
type IntrospectionEndpointConfig struct {
	ent.Schema
}

// Fields of the IntrospectionEndpointConfig.
func (IntrospectionEndpointConfig) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id" hcl:"id"`),
		field.String("endpoint").Unique().NotEmpty().StructTag(`json:"endpoint" hcl:"endpoint"`),
	}
}

// Edges of the IntrospectionEndpointConfig.
func (IntrospectionEndpointConfig) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("service", Service.Type).Ref("service_introspection_endpoint_config").Unique().Required(),
	}
}
