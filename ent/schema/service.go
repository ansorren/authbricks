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
		field.Strings("scopes").StructTag(`json:"scopes" hcl:"scopes"`),
	}
}

// Edges of the Service.
func (Service) Edges() []ent.Edge {
	return []ent.Edge{
		// TODO: Maybe an edge to user pool?
		edge.To("service_config", ServiceConfig.Type).Unique(),
		edge.To("applications", Application.Type),
	}
}
