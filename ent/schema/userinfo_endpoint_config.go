package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// UserInfoEndpointConfig holds the schema definition for the UserInfoEndpointConfig entity.
type UserInfoEndpointConfig struct {
	ent.Schema
}

// Fields of the UserInfoEndpointConfig.
func (UserInfoEndpointConfig) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id" hcl:"id"`),
		field.String("endpoint").Unique().NotEmpty().StructTag(`json:"endpoint" hcl:"endpoint"`),
	}
}

// Edges of the UserInfoEndpointConfig.
func (UserInfoEndpointConfig) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("service", Service.Type).Ref("service_user_info_endpoint_config").Unique().Required(),
	}
}
