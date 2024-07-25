package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// AuthorizationCode holds the schema definition for the AuthorizationCode entity.
type AuthorizationCode struct {
	ent.Schema
}

// Fields of the AuthorizationCode.
func (AuthorizationCode) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id"`),
		field.String("application").StructTag(`json:"application"`),
		field.String("code_challenge").StructTag(`json:"code_challenge"`),
		field.String("code_challenge_method").StructTag(`json:"code_challenge_method"`),
		field.Time("created_at").StructTag(`json:"created_at"`),
		field.Time("auth_time").StructTag(`json:"auth_time"`),
		field.String("redirect_uri").StructTag(`json:"redirect_uri"`),
		field.String("nonce").StructTag(`json:"nonce"`),
		field.String("service").StructTag(`json:"service"`),
		field.String("state").StructTag(`json:"state"`),
		field.String("subject").StructTag(`json:"subject"`),
		field.String("granted_scopes").StructTag(`json:"granted_scopes"`),
	}
}

// Edges of the AuthorizationCode.
func (AuthorizationCode) Edges() []ent.Edge {
	return nil
}
