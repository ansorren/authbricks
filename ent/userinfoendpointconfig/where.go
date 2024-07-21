// Code generated by ent, DO NOT EDIT.

package userinfoendpointconfig

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"go.authbricks.com/bricks/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldLTE(FieldID, id))
}

// IDEqualFold applies the EqualFold predicate on the ID field.
func IDEqualFold(id string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldEqualFold(FieldID, id))
}

// IDContainsFold applies the ContainsFold predicate on the ID field.
func IDContainsFold(id string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldContainsFold(FieldID, id))
}

// Endpoint applies equality check predicate on the "endpoint" field. It's identical to EndpointEQ.
func Endpoint(v string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldEQ(FieldEndpoint, v))
}

// EndpointEQ applies the EQ predicate on the "endpoint" field.
func EndpointEQ(v string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldEQ(FieldEndpoint, v))
}

// EndpointNEQ applies the NEQ predicate on the "endpoint" field.
func EndpointNEQ(v string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldNEQ(FieldEndpoint, v))
}

// EndpointIn applies the In predicate on the "endpoint" field.
func EndpointIn(vs ...string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldIn(FieldEndpoint, vs...))
}

// EndpointNotIn applies the NotIn predicate on the "endpoint" field.
func EndpointNotIn(vs ...string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldNotIn(FieldEndpoint, vs...))
}

// EndpointGT applies the GT predicate on the "endpoint" field.
func EndpointGT(v string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldGT(FieldEndpoint, v))
}

// EndpointGTE applies the GTE predicate on the "endpoint" field.
func EndpointGTE(v string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldGTE(FieldEndpoint, v))
}

// EndpointLT applies the LT predicate on the "endpoint" field.
func EndpointLT(v string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldLT(FieldEndpoint, v))
}

// EndpointLTE applies the LTE predicate on the "endpoint" field.
func EndpointLTE(v string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldLTE(FieldEndpoint, v))
}

// EndpointContains applies the Contains predicate on the "endpoint" field.
func EndpointContains(v string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldContains(FieldEndpoint, v))
}

// EndpointHasPrefix applies the HasPrefix predicate on the "endpoint" field.
func EndpointHasPrefix(v string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldHasPrefix(FieldEndpoint, v))
}

// EndpointHasSuffix applies the HasSuffix predicate on the "endpoint" field.
func EndpointHasSuffix(v string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldHasSuffix(FieldEndpoint, v))
}

// EndpointEqualFold applies the EqualFold predicate on the "endpoint" field.
func EndpointEqualFold(v string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldEqualFold(FieldEndpoint, v))
}

// EndpointContainsFold applies the ContainsFold predicate on the "endpoint" field.
func EndpointContainsFold(v string) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.FieldContainsFold(FieldEndpoint, v))
}

// HasService applies the HasEdge predicate on the "service" edge.
func HasService() predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, ServiceTable, ServiceColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasServiceWith applies the HasEdge predicate on the "service" edge with a given conditions (other predicates).
func HasServiceWith(preds ...predicate.Service) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(func(s *sql.Selector) {
		step := newServiceStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.UserInfoEndpointConfig) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.AndPredicates(predicates...))
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.UserInfoEndpointConfig) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.OrPredicates(predicates...))
}

// Not applies the not operator on the given predicate.
func Not(p predicate.UserInfoEndpointConfig) predicate.UserInfoEndpointConfig {
	return predicate.UserInfoEndpointConfig(sql.NotPredicates(p))
}
