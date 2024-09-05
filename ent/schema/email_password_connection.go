package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// EmailPasswordConnection holds the schema definition for the EmailPasswordConnection entity.
type EmailPasswordConnection struct {
	ent.Schema
}

// Fields of the EmailPasswordConnection.
func (EmailPasswordConnection) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id" hcl:"id"`),
		field.Bool("enabled").Default(false).StructTag(`json:"enabled" hcl:"enabled"`),
	}
}

// Edges of the EmailPasswordConnection.
func (EmailPasswordConnection) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("connection_config", ConnectionConfig.Type).Ref("email_password_connection").Unique().Required(),
		edge.To("users", User.Type).Unique(),
	}
}
