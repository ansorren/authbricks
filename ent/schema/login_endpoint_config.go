package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// LoginEndpointConfig holds the schema definition for the LoginEndpointConfig entity.
type LoginEndpointConfig struct {
	ent.Schema
}

// Fields of the LoginEndpointConfig.
func (LoginEndpointConfig) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id" hcl:"id"`),
		field.String("endpoint").Unique().NotEmpty().StructTag(`json:"endpoint" hcl:"endpoint"`),
		field.Int64("session_timeout").Positive().StructTag(`json:"session_timeout" hcl:"session_timeout"`),
	}
}

// Edges of the LoginEndpointConfig.
func (LoginEndpointConfig) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("service", Service.Type).Ref("service_login_endpoint_config").Unique().Required(),
	}
}
