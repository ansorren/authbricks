package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// RefreshToken holds the schema definition for the RefreshToken entity.
type RefreshToken struct {
	ent.Schema
}

// Fields of the RefreshToken.
func (RefreshToken) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id"`),
		field.String("application").StructTag(`json:"application"`),
		field.String("service").StructTag(`json:"service"`),
		field.String("scopes").StructTag(`json:"scopes"`),
		field.Int64("created_at").Positive().StructTag(`json:"created_at"`),
		field.String("access_token_id").StructTag(`json:"access_token_id"`),
		field.Int64("lifetime").Positive().StructTag(`json:"lifetime"`),
		field.String("subject").StructTag(`json:"subject"`),
		field.String("key_id").StructTag(`json:"key_id"`),
		field.Time("auth_time").StructTag(`json:"auth_time"`),
	}
}

func (RefreshToken) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("access_token_id").Unique(),
	}
}

// Edges of the RefreshToken.
func (RefreshToken) Edges() []ent.Edge {
	return nil
}
