package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// OAuthClient holds the schema definition for the OAuthClient entity.
type OAuthClient struct {
	ent.Schema
}

// Fields of the OAuthClient.
func (OAuthClient) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id"`),
		field.String("name").Unique().NotEmpty().StructTag(`json:"name"`),
		field.Bool("public").Default(false).Nillable().StructTag(`json:"public"`),
	}
}

// Edges of the OAuthClient.
func (OAuthClient) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("m2m_grants", M2MGrant.Type).Unique(),
		edge.To("code_grants", CodeGrant.Type).Unique(),
		edge.To("credentials", Credentials.Type),
		edge.From("server", OAuthServer.Type).Ref("clients").Unique(),
	}
}
