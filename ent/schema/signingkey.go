package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// SigningKey holds the schema definition for the SigningKey entity.
type SigningKey struct {
	ent.Schema
}

// Fields of the SigningKey.
func (SigningKey) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id"`),
		field.String("key").Sensitive().NotEmpty(),
	}
}

// Edges of the SigningKey.
func (SigningKey) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("key_set", KeySet.Type).Ref("signing_keys").Unique(),
	}
}
