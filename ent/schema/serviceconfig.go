package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// ServiceConfig holds the schema definition for the ServiceConfig entity.
type ServiceConfig struct {
	ent.Schema
}

// Fields of the ServiceConfig.
func (ServiceConfig) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id" hcl:"id"`),
	}
}

// Edges of the ServiceConfig.
func (ServiceConfig) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("service", Service.Type).Ref("service_config").Unique().Required(),
		edge.To("key_sets", KeySet.Type),
	}
}
