package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// M2MGrant holds the schema definition for the M2MGrant entity.
type M2MGrant struct {
	ent.Schema
}

// Fields of the M2MGrant.
func (M2MGrant) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id"`),
		field.Strings("scopes").StructTag(`json:"scopes"`),
	}
}

// Edges of the M2MGrant.
func (M2MGrant) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("application", Application.Type).Ref("m2m_grant").Unique(),
	}
}
