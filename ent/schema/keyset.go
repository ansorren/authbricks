package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// KeySet holds the schema definition for the KeySet entity.
type KeySet struct {
	ent.Schema
}

// Fields of the KeySet.
func (KeySet) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id" hcl:"id"`),
	}
}

// Edges of the KeySet.
func (KeySet) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("service_config", ServiceConfig.Type).Ref("key_sets").Unique(),
		edge.To("signing_keys", SigningKey.Type),
	}
}
