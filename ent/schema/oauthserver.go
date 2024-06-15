package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
)

// OAuthServer holds the schema definition for the OAuthServer entity.
type OAuthServer struct {
	ent.Schema
}

// Fields of the OAuthServer.
func (OAuthServer) Fields() []ent.Field {
	return nil
}

// Edges of the OAuthServer.
func (OAuthServer) Edges() []ent.Edge {
	return []ent.Edge{
		// TODO: Maybe an edge to user pool?
		edge.To("key_set", KeySet.Type).Unique(),
		edge.To("clients", OAuthClient.Type),
	}
}
