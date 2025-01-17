// Code generated by ent, DO NOT EDIT.

package user

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"go.authbricks.com/bricks/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id string) predicate.User {
	return predicate.User(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id string) predicate.User {
	return predicate.User(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id string) predicate.User {
	return predicate.User(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...string) predicate.User {
	return predicate.User(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...string) predicate.User {
	return predicate.User(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id string) predicate.User {
	return predicate.User(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id string) predicate.User {
	return predicate.User(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id string) predicate.User {
	return predicate.User(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id string) predicate.User {
	return predicate.User(sql.FieldLTE(FieldID, id))
}

// IDEqualFold applies the EqualFold predicate on the ID field.
func IDEqualFold(id string) predicate.User {
	return predicate.User(sql.FieldEqualFold(FieldID, id))
}

// IDContainsFold applies the ContainsFold predicate on the ID field.
func IDContainsFold(id string) predicate.User {
	return predicate.User(sql.FieldContainsFold(FieldID, id))
}

// Username applies equality check predicate on the "username" field. It's identical to UsernameEQ.
func Username(v string) predicate.User {
	return predicate.User(sql.FieldEQ(FieldUsername, v))
}

// HashedPassword applies equality check predicate on the "hashed_password" field. It's identical to HashedPasswordEQ.
func HashedPassword(v string) predicate.User {
	return predicate.User(sql.FieldEQ(FieldHashedPassword, v))
}

// UsernameEQ applies the EQ predicate on the "username" field.
func UsernameEQ(v string) predicate.User {
	return predicate.User(sql.FieldEQ(FieldUsername, v))
}

// UsernameNEQ applies the NEQ predicate on the "username" field.
func UsernameNEQ(v string) predicate.User {
	return predicate.User(sql.FieldNEQ(FieldUsername, v))
}

// UsernameIn applies the In predicate on the "username" field.
func UsernameIn(vs ...string) predicate.User {
	return predicate.User(sql.FieldIn(FieldUsername, vs...))
}

// UsernameNotIn applies the NotIn predicate on the "username" field.
func UsernameNotIn(vs ...string) predicate.User {
	return predicate.User(sql.FieldNotIn(FieldUsername, vs...))
}

// UsernameGT applies the GT predicate on the "username" field.
func UsernameGT(v string) predicate.User {
	return predicate.User(sql.FieldGT(FieldUsername, v))
}

// UsernameGTE applies the GTE predicate on the "username" field.
func UsernameGTE(v string) predicate.User {
	return predicate.User(sql.FieldGTE(FieldUsername, v))
}

// UsernameLT applies the LT predicate on the "username" field.
func UsernameLT(v string) predicate.User {
	return predicate.User(sql.FieldLT(FieldUsername, v))
}

// UsernameLTE applies the LTE predicate on the "username" field.
func UsernameLTE(v string) predicate.User {
	return predicate.User(sql.FieldLTE(FieldUsername, v))
}

// UsernameContains applies the Contains predicate on the "username" field.
func UsernameContains(v string) predicate.User {
	return predicate.User(sql.FieldContains(FieldUsername, v))
}

// UsernameHasPrefix applies the HasPrefix predicate on the "username" field.
func UsernameHasPrefix(v string) predicate.User {
	return predicate.User(sql.FieldHasPrefix(FieldUsername, v))
}

// UsernameHasSuffix applies the HasSuffix predicate on the "username" field.
func UsernameHasSuffix(v string) predicate.User {
	return predicate.User(sql.FieldHasSuffix(FieldUsername, v))
}

// UsernameEqualFold applies the EqualFold predicate on the "username" field.
func UsernameEqualFold(v string) predicate.User {
	return predicate.User(sql.FieldEqualFold(FieldUsername, v))
}

// UsernameContainsFold applies the ContainsFold predicate on the "username" field.
func UsernameContainsFold(v string) predicate.User {
	return predicate.User(sql.FieldContainsFold(FieldUsername, v))
}

// HashedPasswordEQ applies the EQ predicate on the "hashed_password" field.
func HashedPasswordEQ(v string) predicate.User {
	return predicate.User(sql.FieldEQ(FieldHashedPassword, v))
}

// HashedPasswordNEQ applies the NEQ predicate on the "hashed_password" field.
func HashedPasswordNEQ(v string) predicate.User {
	return predicate.User(sql.FieldNEQ(FieldHashedPassword, v))
}

// HashedPasswordIn applies the In predicate on the "hashed_password" field.
func HashedPasswordIn(vs ...string) predicate.User {
	return predicate.User(sql.FieldIn(FieldHashedPassword, vs...))
}

// HashedPasswordNotIn applies the NotIn predicate on the "hashed_password" field.
func HashedPasswordNotIn(vs ...string) predicate.User {
	return predicate.User(sql.FieldNotIn(FieldHashedPassword, vs...))
}

// HashedPasswordGT applies the GT predicate on the "hashed_password" field.
func HashedPasswordGT(v string) predicate.User {
	return predicate.User(sql.FieldGT(FieldHashedPassword, v))
}

// HashedPasswordGTE applies the GTE predicate on the "hashed_password" field.
func HashedPasswordGTE(v string) predicate.User {
	return predicate.User(sql.FieldGTE(FieldHashedPassword, v))
}

// HashedPasswordLT applies the LT predicate on the "hashed_password" field.
func HashedPasswordLT(v string) predicate.User {
	return predicate.User(sql.FieldLT(FieldHashedPassword, v))
}

// HashedPasswordLTE applies the LTE predicate on the "hashed_password" field.
func HashedPasswordLTE(v string) predicate.User {
	return predicate.User(sql.FieldLTE(FieldHashedPassword, v))
}

// HashedPasswordContains applies the Contains predicate on the "hashed_password" field.
func HashedPasswordContains(v string) predicate.User {
	return predicate.User(sql.FieldContains(FieldHashedPassword, v))
}

// HashedPasswordHasPrefix applies the HasPrefix predicate on the "hashed_password" field.
func HashedPasswordHasPrefix(v string) predicate.User {
	return predicate.User(sql.FieldHasPrefix(FieldHashedPassword, v))
}

// HashedPasswordHasSuffix applies the HasSuffix predicate on the "hashed_password" field.
func HashedPasswordHasSuffix(v string) predicate.User {
	return predicate.User(sql.FieldHasSuffix(FieldHashedPassword, v))
}

// HashedPasswordEqualFold applies the EqualFold predicate on the "hashed_password" field.
func HashedPasswordEqualFold(v string) predicate.User {
	return predicate.User(sql.FieldEqualFold(FieldHashedPassword, v))
}

// HashedPasswordContainsFold applies the ContainsFold predicate on the "hashed_password" field.
func HashedPasswordContainsFold(v string) predicate.User {
	return predicate.User(sql.FieldContainsFold(FieldHashedPassword, v))
}

// HasStandardClaims applies the HasEdge predicate on the "standard_claims" edge.
func HasStandardClaims() predicate.User {
	return predicate.User(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2O, false, StandardClaimsTable, StandardClaimsColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasStandardClaimsWith applies the HasEdge predicate on the "standard_claims" edge with a given conditions (other predicates).
func HasStandardClaimsWith(preds ...predicate.StandardClaims) predicate.User {
	return predicate.User(func(s *sql.Selector) {
		step := newStandardClaimsStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasEmailPasswordConnection applies the HasEdge predicate on the "email_password_connection" edge.
func HasEmailPasswordConnection() predicate.User {
	return predicate.User(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, EmailPasswordConnectionTable, EmailPasswordConnectionColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasEmailPasswordConnectionWith applies the HasEdge predicate on the "email_password_connection" edge with a given conditions (other predicates).
func HasEmailPasswordConnectionWith(preds ...predicate.EmailPasswordConnection) predicate.User {
	return predicate.User(func(s *sql.Selector) {
		step := newEmailPasswordConnectionStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasOidcConnections applies the HasEdge predicate on the "oidc_connections" edge.
func HasOidcConnections() predicate.User {
	return predicate.User(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, OidcConnectionsTable, OidcConnectionsColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasOidcConnectionsWith applies the HasEdge predicate on the "oidc_connections" edge with a given conditions (other predicates).
func HasOidcConnectionsWith(preds ...predicate.OIDCConnection) predicate.User {
	return predicate.User(func(s *sql.Selector) {
		step := newOidcConnectionsStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.User) predicate.User {
	return predicate.User(sql.AndPredicates(predicates...))
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.User) predicate.User {
	return predicate.User(sql.OrPredicates(predicates...))
}

// Not applies the not operator on the given predicate.
func Not(p predicate.User) predicate.User {
	return predicate.User(sql.NotPredicates(p))
}
