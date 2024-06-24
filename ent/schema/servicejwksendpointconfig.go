package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// ServiceJWKSEndpointConfig holds the schema definition for the ServiceJWKSEndpointConfig entity.
type ServiceJWKSEndpointConfig struct {
	ent.Schema
}

// Fields of the ServiceJWKSEndpointConfig.
func (ServiceJWKSEndpointConfig) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id" hcl:"id"`),
		field.String("endpoint").Unique().NotEmpty().StructTag(`json:"endpoint" hcl:"endpoint"`),
	}
}

// Edges of the ServiceJWKSEndpointConfig.
func (ServiceJWKSEndpointConfig) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("service", Service.Type).Ref("service_jwks_endpoint_config").Unique().Required(),
	}
}
