package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// User holds the schema definition for the Users entity.
type User struct {
	ent.Schema
}

// Fields of the User.
func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id"`),
		field.String("username").NotEmpty().Unique().StructTag(`json:"username"`),
		field.String("password").NotEmpty().StructTag(`json:"password"`),
	}
}

// Edges of the User.
func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user_pool", UserPool.Type).Ref("users").Unique(),
		edge.To("standard_claims", StandardClaims.Type).Unique(),
	}
}
