// Code generated by ent, DO NOT EDIT.

package keyset

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"go.authbricks.com/bricks/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id string) predicate.KeySet {
	return predicate.KeySet(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id string) predicate.KeySet {
	return predicate.KeySet(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id string) predicate.KeySet {
	return predicate.KeySet(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...string) predicate.KeySet {
	return predicate.KeySet(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...string) predicate.KeySet {
	return predicate.KeySet(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id string) predicate.KeySet {
	return predicate.KeySet(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id string) predicate.KeySet {
	return predicate.KeySet(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id string) predicate.KeySet {
	return predicate.KeySet(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id string) predicate.KeySet {
	return predicate.KeySet(sql.FieldLTE(FieldID, id))
}

// IDEqualFold applies the EqualFold predicate on the ID field.
func IDEqualFold(id string) predicate.KeySet {
	return predicate.KeySet(sql.FieldEqualFold(FieldID, id))
}

// IDContainsFold applies the ContainsFold predicate on the ID field.
func IDContainsFold(id string) predicate.KeySet {
	return predicate.KeySet(sql.FieldContainsFold(FieldID, id))
}

// HasOauthServer applies the HasEdge predicate on the "oauth_server" edge.
func HasOauthServer() predicate.KeySet {
	return predicate.KeySet(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, OauthServerTable, OauthServerColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasOauthServerWith applies the HasEdge predicate on the "oauth_server" edge with a given conditions (other predicates).
func HasOauthServerWith(preds ...predicate.OAuthServer) predicate.KeySet {
	return predicate.KeySet(func(s *sql.Selector) {
		step := newOauthServerStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasSigningKeys applies the HasEdge predicate on the "signing_keys" edge.
func HasSigningKeys() predicate.KeySet {
	return predicate.KeySet(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, SigningKeysTable, SigningKeysColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasSigningKeysWith applies the HasEdge predicate on the "signing_keys" edge with a given conditions (other predicates).
func HasSigningKeysWith(preds ...predicate.SigningKey) predicate.KeySet {
	return predicate.KeySet(func(s *sql.Selector) {
		step := newSigningKeysStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.KeySet) predicate.KeySet {
	return predicate.KeySet(sql.AndPredicates(predicates...))
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.KeySet) predicate.KeySet {
	return predicate.KeySet(sql.OrPredicates(predicates...))
}

// Not applies the not operator on the given predicate.
func Not(p predicate.KeySet) predicate.KeySet {
	return predicate.KeySet(sql.NotPredicates(p))
}