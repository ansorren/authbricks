// Code generated by ent, DO NOT EDIT.

package oidcconnection

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"go.authbricks.com/bricks/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldLTE(FieldID, id))
}

// IDEqualFold applies the EqualFold predicate on the ID field.
func IDEqualFold(id string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldEqualFold(FieldID, id))
}

// IDContainsFold applies the ContainsFold predicate on the ID field.
func IDContainsFold(id string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldContainsFold(FieldID, id))
}

// Enabled applies equality check predicate on the "enabled" field. It's identical to EnabledEQ.
func Enabled(v bool) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldEQ(FieldEnabled, v))
}

// ClientID applies equality check predicate on the "client_id" field. It's identical to ClientIDEQ.
func ClientID(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldEQ(FieldClientID, v))
}

// ClientSecret applies equality check predicate on the "client_secret" field. It's identical to ClientSecretEQ.
func ClientSecret(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldEQ(FieldClientSecret, v))
}

// RedirectURI applies equality check predicate on the "redirect_uri" field. It's identical to RedirectURIEQ.
func RedirectURI(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldEQ(FieldRedirectURI, v))
}

// WellKnownOpenidConfiguration applies equality check predicate on the "well_known_openid_configuration" field. It's identical to WellKnownOpenidConfigurationEQ.
func WellKnownOpenidConfiguration(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldEQ(FieldWellKnownOpenidConfiguration, v))
}

// EnabledEQ applies the EQ predicate on the "enabled" field.
func EnabledEQ(v bool) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldEQ(FieldEnabled, v))
}

// EnabledNEQ applies the NEQ predicate on the "enabled" field.
func EnabledNEQ(v bool) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldNEQ(FieldEnabled, v))
}

// ClientIDEQ applies the EQ predicate on the "client_id" field.
func ClientIDEQ(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldEQ(FieldClientID, v))
}

// ClientIDNEQ applies the NEQ predicate on the "client_id" field.
func ClientIDNEQ(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldNEQ(FieldClientID, v))
}

// ClientIDIn applies the In predicate on the "client_id" field.
func ClientIDIn(vs ...string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldIn(FieldClientID, vs...))
}

// ClientIDNotIn applies the NotIn predicate on the "client_id" field.
func ClientIDNotIn(vs ...string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldNotIn(FieldClientID, vs...))
}

// ClientIDGT applies the GT predicate on the "client_id" field.
func ClientIDGT(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldGT(FieldClientID, v))
}

// ClientIDGTE applies the GTE predicate on the "client_id" field.
func ClientIDGTE(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldGTE(FieldClientID, v))
}

// ClientIDLT applies the LT predicate on the "client_id" field.
func ClientIDLT(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldLT(FieldClientID, v))
}

// ClientIDLTE applies the LTE predicate on the "client_id" field.
func ClientIDLTE(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldLTE(FieldClientID, v))
}

// ClientIDContains applies the Contains predicate on the "client_id" field.
func ClientIDContains(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldContains(FieldClientID, v))
}

// ClientIDHasPrefix applies the HasPrefix predicate on the "client_id" field.
func ClientIDHasPrefix(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldHasPrefix(FieldClientID, v))
}

// ClientIDHasSuffix applies the HasSuffix predicate on the "client_id" field.
func ClientIDHasSuffix(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldHasSuffix(FieldClientID, v))
}

// ClientIDIsNil applies the IsNil predicate on the "client_id" field.
func ClientIDIsNil() predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldIsNull(FieldClientID))
}

// ClientIDNotNil applies the NotNil predicate on the "client_id" field.
func ClientIDNotNil() predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldNotNull(FieldClientID))
}

// ClientIDEqualFold applies the EqualFold predicate on the "client_id" field.
func ClientIDEqualFold(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldEqualFold(FieldClientID, v))
}

// ClientIDContainsFold applies the ContainsFold predicate on the "client_id" field.
func ClientIDContainsFold(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldContainsFold(FieldClientID, v))
}

// ClientSecretEQ applies the EQ predicate on the "client_secret" field.
func ClientSecretEQ(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldEQ(FieldClientSecret, v))
}

// ClientSecretNEQ applies the NEQ predicate on the "client_secret" field.
func ClientSecretNEQ(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldNEQ(FieldClientSecret, v))
}

// ClientSecretIn applies the In predicate on the "client_secret" field.
func ClientSecretIn(vs ...string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldIn(FieldClientSecret, vs...))
}

// ClientSecretNotIn applies the NotIn predicate on the "client_secret" field.
func ClientSecretNotIn(vs ...string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldNotIn(FieldClientSecret, vs...))
}

// ClientSecretGT applies the GT predicate on the "client_secret" field.
func ClientSecretGT(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldGT(FieldClientSecret, v))
}

// ClientSecretGTE applies the GTE predicate on the "client_secret" field.
func ClientSecretGTE(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldGTE(FieldClientSecret, v))
}

// ClientSecretLT applies the LT predicate on the "client_secret" field.
func ClientSecretLT(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldLT(FieldClientSecret, v))
}

// ClientSecretLTE applies the LTE predicate on the "client_secret" field.
func ClientSecretLTE(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldLTE(FieldClientSecret, v))
}

// ClientSecretContains applies the Contains predicate on the "client_secret" field.
func ClientSecretContains(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldContains(FieldClientSecret, v))
}

// ClientSecretHasPrefix applies the HasPrefix predicate on the "client_secret" field.
func ClientSecretHasPrefix(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldHasPrefix(FieldClientSecret, v))
}

// ClientSecretHasSuffix applies the HasSuffix predicate on the "client_secret" field.
func ClientSecretHasSuffix(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldHasSuffix(FieldClientSecret, v))
}

// ClientSecretIsNil applies the IsNil predicate on the "client_secret" field.
func ClientSecretIsNil() predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldIsNull(FieldClientSecret))
}

// ClientSecretNotNil applies the NotNil predicate on the "client_secret" field.
func ClientSecretNotNil() predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldNotNull(FieldClientSecret))
}

// ClientSecretEqualFold applies the EqualFold predicate on the "client_secret" field.
func ClientSecretEqualFold(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldEqualFold(FieldClientSecret, v))
}

// ClientSecretContainsFold applies the ContainsFold predicate on the "client_secret" field.
func ClientSecretContainsFold(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldContainsFold(FieldClientSecret, v))
}

// ScopesIsNil applies the IsNil predicate on the "scopes" field.
func ScopesIsNil() predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldIsNull(FieldScopes))
}

// ScopesNotNil applies the NotNil predicate on the "scopes" field.
func ScopesNotNil() predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldNotNull(FieldScopes))
}

// RedirectURIEQ applies the EQ predicate on the "redirect_uri" field.
func RedirectURIEQ(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldEQ(FieldRedirectURI, v))
}

// RedirectURINEQ applies the NEQ predicate on the "redirect_uri" field.
func RedirectURINEQ(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldNEQ(FieldRedirectURI, v))
}

// RedirectURIIn applies the In predicate on the "redirect_uri" field.
func RedirectURIIn(vs ...string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldIn(FieldRedirectURI, vs...))
}

// RedirectURINotIn applies the NotIn predicate on the "redirect_uri" field.
func RedirectURINotIn(vs ...string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldNotIn(FieldRedirectURI, vs...))
}

// RedirectURIGT applies the GT predicate on the "redirect_uri" field.
func RedirectURIGT(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldGT(FieldRedirectURI, v))
}

// RedirectURIGTE applies the GTE predicate on the "redirect_uri" field.
func RedirectURIGTE(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldGTE(FieldRedirectURI, v))
}

// RedirectURILT applies the LT predicate on the "redirect_uri" field.
func RedirectURILT(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldLT(FieldRedirectURI, v))
}

// RedirectURILTE applies the LTE predicate on the "redirect_uri" field.
func RedirectURILTE(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldLTE(FieldRedirectURI, v))
}

// RedirectURIContains applies the Contains predicate on the "redirect_uri" field.
func RedirectURIContains(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldContains(FieldRedirectURI, v))
}

// RedirectURIHasPrefix applies the HasPrefix predicate on the "redirect_uri" field.
func RedirectURIHasPrefix(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldHasPrefix(FieldRedirectURI, v))
}

// RedirectURIHasSuffix applies the HasSuffix predicate on the "redirect_uri" field.
func RedirectURIHasSuffix(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldHasSuffix(FieldRedirectURI, v))
}

// RedirectURIIsNil applies the IsNil predicate on the "redirect_uri" field.
func RedirectURIIsNil() predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldIsNull(FieldRedirectURI))
}

// RedirectURINotNil applies the NotNil predicate on the "redirect_uri" field.
func RedirectURINotNil() predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldNotNull(FieldRedirectURI))
}

// RedirectURIEqualFold applies the EqualFold predicate on the "redirect_uri" field.
func RedirectURIEqualFold(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldEqualFold(FieldRedirectURI, v))
}

// RedirectURIContainsFold applies the ContainsFold predicate on the "redirect_uri" field.
func RedirectURIContainsFold(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldContainsFold(FieldRedirectURI, v))
}

// WellKnownOpenidConfigurationEQ applies the EQ predicate on the "well_known_openid_configuration" field.
func WellKnownOpenidConfigurationEQ(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldEQ(FieldWellKnownOpenidConfiguration, v))
}

// WellKnownOpenidConfigurationNEQ applies the NEQ predicate on the "well_known_openid_configuration" field.
func WellKnownOpenidConfigurationNEQ(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldNEQ(FieldWellKnownOpenidConfiguration, v))
}

// WellKnownOpenidConfigurationIn applies the In predicate on the "well_known_openid_configuration" field.
func WellKnownOpenidConfigurationIn(vs ...string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldIn(FieldWellKnownOpenidConfiguration, vs...))
}

// WellKnownOpenidConfigurationNotIn applies the NotIn predicate on the "well_known_openid_configuration" field.
func WellKnownOpenidConfigurationNotIn(vs ...string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldNotIn(FieldWellKnownOpenidConfiguration, vs...))
}

// WellKnownOpenidConfigurationGT applies the GT predicate on the "well_known_openid_configuration" field.
func WellKnownOpenidConfigurationGT(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldGT(FieldWellKnownOpenidConfiguration, v))
}

// WellKnownOpenidConfigurationGTE applies the GTE predicate on the "well_known_openid_configuration" field.
func WellKnownOpenidConfigurationGTE(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldGTE(FieldWellKnownOpenidConfiguration, v))
}

// WellKnownOpenidConfigurationLT applies the LT predicate on the "well_known_openid_configuration" field.
func WellKnownOpenidConfigurationLT(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldLT(FieldWellKnownOpenidConfiguration, v))
}

// WellKnownOpenidConfigurationLTE applies the LTE predicate on the "well_known_openid_configuration" field.
func WellKnownOpenidConfigurationLTE(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldLTE(FieldWellKnownOpenidConfiguration, v))
}

// WellKnownOpenidConfigurationContains applies the Contains predicate on the "well_known_openid_configuration" field.
func WellKnownOpenidConfigurationContains(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldContains(FieldWellKnownOpenidConfiguration, v))
}

// WellKnownOpenidConfigurationHasPrefix applies the HasPrefix predicate on the "well_known_openid_configuration" field.
func WellKnownOpenidConfigurationHasPrefix(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldHasPrefix(FieldWellKnownOpenidConfiguration, v))
}

// WellKnownOpenidConfigurationHasSuffix applies the HasSuffix predicate on the "well_known_openid_configuration" field.
func WellKnownOpenidConfigurationHasSuffix(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldHasSuffix(FieldWellKnownOpenidConfiguration, v))
}

// WellKnownOpenidConfigurationIsNil applies the IsNil predicate on the "well_known_openid_configuration" field.
func WellKnownOpenidConfigurationIsNil() predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldIsNull(FieldWellKnownOpenidConfiguration))
}

// WellKnownOpenidConfigurationNotNil applies the NotNil predicate on the "well_known_openid_configuration" field.
func WellKnownOpenidConfigurationNotNil() predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldNotNull(FieldWellKnownOpenidConfiguration))
}

// WellKnownOpenidConfigurationEqualFold applies the EqualFold predicate on the "well_known_openid_configuration" field.
func WellKnownOpenidConfigurationEqualFold(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldEqualFold(FieldWellKnownOpenidConfiguration, v))
}

// WellKnownOpenidConfigurationContainsFold applies the ContainsFold predicate on the "well_known_openid_configuration" field.
func WellKnownOpenidConfigurationContainsFold(v string) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.FieldContainsFold(FieldWellKnownOpenidConfiguration, v))
}

// HasConnectionConfig applies the HasEdge predicate on the "connection_config" edge.
func HasConnectionConfig() predicate.OIDCConnection {
	return predicate.OIDCConnection(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, ConnectionConfigTable, ConnectionConfigColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasConnectionConfigWith applies the HasEdge predicate on the "connection_config" edge with a given conditions (other predicates).
func HasConnectionConfigWith(preds ...predicate.ConnectionConfig) predicate.OIDCConnection {
	return predicate.OIDCConnection(func(s *sql.Selector) {
		step := newConnectionConfigStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasUsers applies the HasEdge predicate on the "users" edge.
func HasUsers() predicate.OIDCConnection {
	return predicate.OIDCConnection(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2O, false, UsersTable, UsersColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasUsersWith applies the HasEdge predicate on the "users" edge with a given conditions (other predicates).
func HasUsersWith(preds ...predicate.User) predicate.OIDCConnection {
	return predicate.OIDCConnection(func(s *sql.Selector) {
		step := newUsersStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.OIDCConnection) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.AndPredicates(predicates...))
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.OIDCConnection) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.OrPredicates(predicates...))
}

// Not applies the not operator on the given predicate.
func Not(p predicate.OIDCConnection) predicate.OIDCConnection {
	return predicate.OIDCConnection(sql.NotPredicates(p))
}