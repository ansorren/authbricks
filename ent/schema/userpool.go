package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// UserPool holds the schema definition for the UserPool entity.
type UserPool struct {
	ent.Schema
}

// Fields of the UserPool.
func (UserPool) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id" hcl:"id"`),
	}
}

// Edges of the UserPool.
func (UserPool) Edges() []ent.Edge {
	return []ent.Edge{
		// TODO: Maybe an edge to server?
		edge.To("users", User.Type),
	}
}
