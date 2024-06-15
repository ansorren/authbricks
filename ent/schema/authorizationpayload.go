package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// AuthorizationPayload holds the schema definition for the AuthorizationPayload entity.
type AuthorizationPayload struct {
	ent.Schema
}

// Fields of the AuthorizationPayload.
func (AuthorizationPayload) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").NotEmpty().Unique().StructTag(`json:"id"`),
		field.String("code_challenge").StructTag(`json:"code_challenge"`),
		field.String("code_challenge_method").StructTag(`json:"code_challenge_method"`),
		field.String("client_id").StructTag(`json:"client_id"`),
		field.String("nonce").StructTag(`json:"nonce"`),
		field.String("redirect_uri").StructTag(`json:"redirect_uri"`),
		field.String("response_type").StructTag(`json:"response_type"`),
		field.String("scope").StructTag(`json:"scope"`),
		field.String("server_name").StructTag(`json:"server_name"`),
		field.String("state").StructTag(`json:"state"`),
		field.String("response_mode").StructTag(`json:"response_mode"`),
	}
}

// Edges of the AuthorizationPayload.
func (AuthorizationPayload) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("session", Session.Type).Ref("authorization_payload").Unique(),
	}
}
