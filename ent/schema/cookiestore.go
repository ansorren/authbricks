package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// CookieStore holds the schema definition for the CookieStore entity.
type CookieStore struct {
	ent.Schema
}

// Fields of the CookieStore.
func (CookieStore) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id"`),
		field.String("auth_key").NotEmpty().StructTag(`json:"auth_key"`),
		field.String("encryption_key").NotEmpty().StructTag(`json:"encryption_key"`),
	}
}

// Edges of the CookieStore.
func (CookieStore) Edges() []ent.Edge {
	return nil
}
