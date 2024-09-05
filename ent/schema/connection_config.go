package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// ConnectionConfig holds the schema definition for the ConnectionConfig entity.
type ConnectionConfig struct {
	ent.Schema
}

// Fields of the ConnectionConfig.
func (ConnectionConfig) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id" hcl:"id"`),
	}
}

// Edges of the ConnectionConfig.
func (ConnectionConfig) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("service", Service.Type).Unique().Ref("service_connection_config").Required(),
		edge.To("oidc_connections", OIDCConnection.Type),
		edge.To("email_password_connection", EmailPasswordConnection.Type).Unique(),
	}
}
