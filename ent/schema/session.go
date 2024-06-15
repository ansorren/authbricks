package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Session holds the schema definition for the Session entity.
type Session struct {
	ent.Schema
}

// Fields of the Session.
func (Session) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").NotEmpty().Unique().StructTag(`json:"id"`),
		field.Int64("created_at").Positive().StructTag(`json:"created_at"`),
		field.String("server_name").NotEmpty().StructTag(`json:"server_name"`),
	}
}

// Edges of the Session.
func (Session) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("authorization_payload", AuthorizationPayload.Type).Unique(),
	}
}
