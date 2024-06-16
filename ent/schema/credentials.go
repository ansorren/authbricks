package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Credentials holds the schema definition for the Credentials entity.
type Credentials struct {
	ent.Schema
}

// Fields of the Credentials.
func (Credentials) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id"`),
		field.String("client_id").Unique().NotEmpty().StructTag(`json:"client_id"`),
		field.String("client_secret").StructTag(`json:"client_secret"`),
	}
}

// Edges of the Credentials.
func (Credentials) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("oauth_client", Application.Type).Ref("credentials").Unique(),
	}
}
