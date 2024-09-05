package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// OIDCConnection holds the schema definition for the OIDCConnection entity.
type OIDCConnection struct {
	ent.Schema
}

// Fields of the OIDCConnection.
func (OIDCConnection) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id" hcl:"id"`),
		field.Bool("enabled").Default(false).StructTag(`json:"enabled" hcl:"enabled"`),
		field.String("client_id").Optional().StructTag(`json:"client_id" hcl:"client_id"`),
		field.String("client_secret").Optional().StructTag(`json:"client_secret" hcl:"client_secret"`),
		field.Strings("scopes").Optional().StructTag(`json:"scopes" hcl:"scopes"`),
		field.String("redirect_uri").Optional().StructTag(`json:"redirect_uri" hcl:"redirect_uri"`),
		field.String("well_known_openid_configuration").Optional().StructTag(`json:"well_known_openid_configuration" hcl:"well_known_openid_configuration"`),
	}
}

// Edges of the OIDCConnection.
func (OIDCConnection) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("connection_config", ConnectionConfig.Type).Ref("oidc_connections").Unique(),
		edge.To("users", User.Type).Unique(),
	}
}
