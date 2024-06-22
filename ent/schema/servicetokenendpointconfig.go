package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// ServiceTokenEndpointConfig holds the schema definition for the ServiceTokenEndpointConfig entity.
type ServiceTokenEndpointConfig struct {
	ent.Schema
}

// Fields of the ServiceTokenEndpointConfig.
func (ServiceTokenEndpointConfig) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id" hcl:"id"`),
		field.String("endpoint").Unique().NotEmpty().StructTag(`json:"endpoint" hcl:"endpoint"`),
		field.Strings("allowed_authentication_methods").StructTag(`json:"allowed_authentication_methods" hcl:"allowed_authentication_methods"`),
	}
}

// Edges of the ServiceTokenEndpointConfig.
func (ServiceTokenEndpointConfig) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("service", Service.Type).Ref("service_token_endpoint_config").Unique().Required(),
	}
}
