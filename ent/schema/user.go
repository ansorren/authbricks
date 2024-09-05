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
		field.String("username").NotEmpty().StructTag(`json:"username"`),
		field.String("hashed_password").StructTag(`json:"hashed_password"`),
	}
}

// Edges of the User.
func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("standard_claims", StandardClaims.Type).Unique(),
		edge.From("email_password_connection", EmailPasswordConnection.Type).Ref("users").Unique(),
		edge.From("oidc_connections", OIDCConnection.Type).Ref("users").Unique(),
	}
}
