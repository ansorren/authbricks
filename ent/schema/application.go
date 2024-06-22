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
		field.String("id").Unique().NotEmpty().StructTag(`json:"id" hcl:"id"`),
		field.String("name").Unique().NotEmpty().StructTag(`json:"name" hcl:"name"`),
		field.Bool("public").Default(false).StructTag(`json:"public" hcl:"public"`),
		field.String("description").StructTag(`json:"description" hcl:"description"`),
		field.Strings("redirect_uris").StructTag(`json:"redirect_uris" hcl:"redirect_uris"`),
		field.Strings("response_types").StructTag(`json:"response_types" hcl:"response_types"`),
		field.Strings("grant_types").StructTag(`json:"grant_types" hcl:"grant_types"`),
		field.Strings("scopes").StructTag(`json:"scopes" hcl:"scopes"`),
		field.Bool("pkce_required").Default(false).StructTag(`json:"pkce_required" hcl:"pkce_required"`),
		field.Bool("s256_code_challenge_method_required").Default(false).StructTag(`json:"s256_code_challenge_method_required" hcl:"s256_code_challenge_method_required"`),
		field.Strings("allowed_authentication_methods").StructTag(`json:"allowed_authentication_methods" hcl:"allowed_authentication_methods"`),
	}
}

// Edges of the Application.
func (Application) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("credentials", Credentials.Type),
		edge.From("service", Service.Type).Ref("applications").Unique(),
	}
}
