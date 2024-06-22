package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// ServiceUserInfoEndpointConfig holds the schema definition for the ServiceUserInfoEndpointConfig entity.
type ServiceUserInfoEndpointConfig struct {
	ent.Schema
}

// Fields of the ServiceUserInfoEndpointConfig.
func (ServiceUserInfoEndpointConfig) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id" hcl:"id"`),
		field.String("endpoint").Unique().NotEmpty().StructTag(`json:"endpoint" hcl:"endpoint"`),
	}
}

// Edges of the ServiceUserInfoEndpointConfig.
func (ServiceUserInfoEndpointConfig) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("service", Service.Type).Ref("service_user_info_endpoint_config").Unique().Required(),
	}
}
