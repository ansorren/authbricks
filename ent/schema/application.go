package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Application holds the schema definition for the Application entity.
type Application struct {
	ent.Schema
}

// Fields of the Application.
func (Application) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().NotEmpty().StructTag(`json:"id"`),
		field.String("name").Unique().NotEmpty().StructTag(`json:"name"`),
		field.Bool("public").Default(false).Nillable().StructTag(`json:"public"`),
	}
}

// Edges of the Application.
func (Application) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("m2m_grant", M2MGrant.Type).Unique(),
		edge.To("code_grant", CodeGrant.Type).Unique(),
		edge.To("credentials", Credentials.Type),
		edge.From("service", Service.Type).Ref("applications").Unique(),
	}
}
