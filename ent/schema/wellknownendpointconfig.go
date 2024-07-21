package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// WellKnownEndpointConfig holds the schema definition for the WellKnownEndpointConfig entity.
type WellKnownEndpointConfig struct {
	ent.Schema
}

// Fields of the WellKnownEndpointConfig.
func (WellKnownEndpointConfig) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id" hcl:"id"`),
		field.String("endpoint").Unique().NotEmpty().StructTag(`json:"endpoint" hcl:"endpoint"`),
	}
}

// Edges of the WellKnownEndpointConfig.
func (WellKnownEndpointConfig) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("service", Service.Type).Ref("service_well_known_endpoint_config").Unique().Required(),
	}
}
