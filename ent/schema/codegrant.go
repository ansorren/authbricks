package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// CodeGrant holds the schema definition for the CodeGrant entity.
type CodeGrant struct {
	ent.Schema
}

// Fields of the CodeGrant.
func (CodeGrant) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id"`),
		field.Strings("scopes").StructTag(`json:"scopes"`),
		field.Strings("callbacks").StructTag(`json:"callbacks"`),
	}
}

// Edges of the CodeGrant.
func (CodeGrant) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("application", Application.Type).Ref("code_grant").Unique(),
	}
}
