package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// StandardClaims holds the schema definition for the StandardClaims entity.
type StandardClaims struct {
	ent.Schema
}

// Fields of the StandardClaims.
func (StandardClaims) Fields() []ent.Field {
	return []ent.Field{
		field.String("subject").Unique().NotEmpty().StructTag(`json:"sub"`),
		field.String("name").Optional().StructTag(`json:"name,omitempty"`),
		field.String("given_name").Optional().StructTag(`json:"given_name,omitempty"`),
		field.String("family_name").Optional().StructTag(`json:"family_name,omitempty"`),
		field.String("middle_name").Optional().StructTag(`json:"middle_name,omitempty"`),
		field.String("nickname").Optional().StructTag(`json:"nickname,omitempty"`),
		field.String("preferred_username").Optional().StructTag(`json:"preferred_username,omitempty"`),
		field.String("profile").Optional().StructTag(`json:"profile,omitempty"`),
		field.String("picture").Optional().StructTag(`json:"picture,omitempty"`),
		field.String("website").Optional().StructTag(`json:"website,omitempty"`),
		field.String("email").Optional().StructTag(`json:"email,omitempty"`),
		field.Bool("email_verified").Optional().Default(false).StructTag(`json:"email_verified,omitempty"`),
		field.String("gender").Optional().StructTag(`json:"gender,omitempty"`),
		field.String("birthdate").Optional().StructTag(`json:"birthdate,omitempty"`),
		field.String("zoneinfo").Optional().StructTag(`json:"zoneinfo,omitempty"`),
		field.String("locale").Optional().StructTag(`json:"locale,omitempty"`),
		field.String("phone_number").Optional().StructTag(`json:"phone_number,omitempty"`),
		field.Bool("phone_number_verified").Optional().Default(false).StructTag(`json:"phone_number_verified,omitempty"`),
		field.String("address").Optional().StructTag(`json:"address,omitempty"`),
		field.Int64("updated_at").Optional().StructTag(`json:"updated_at,omitempty"`),
	}
}

// Edges of the StandardClaims.
func (StandardClaims) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).Ref("standard_claims").Unique().Required(),
	}
}
