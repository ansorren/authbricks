// Code generated by ent, DO NOT EDIT.

package authorizationpayload

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"go.authbricks.com/bricks/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLTE(FieldID, id))
}

// IDEqualFold applies the EqualFold predicate on the ID field.
func IDEqualFold(id string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEqualFold(FieldID, id))
}

// IDContainsFold applies the ContainsFold predicate on the ID field.
func IDContainsFold(id string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldContainsFold(FieldID, id))
}

// CodeChallenge applies equality check predicate on the "code_challenge" field. It's identical to CodeChallengeEQ.
func CodeChallenge(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldCodeChallenge, v))
}

// CodeChallengeMethod applies equality check predicate on the "code_challenge_method" field. It's identical to CodeChallengeMethodEQ.
func CodeChallengeMethod(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldCodeChallengeMethod, v))
}

// ClientID applies equality check predicate on the "client_id" field. It's identical to ClientIDEQ.
func ClientID(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldClientID, v))
}

// Nonce applies equality check predicate on the "nonce" field. It's identical to NonceEQ.
func Nonce(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldNonce, v))
}

// RedirectURI applies equality check predicate on the "redirect_uri" field. It's identical to RedirectURIEQ.
func RedirectURI(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldRedirectURI, v))
}

// ResponseType applies equality check predicate on the "response_type" field. It's identical to ResponseTypeEQ.
func ResponseType(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldResponseType, v))
}

// Scope applies equality check predicate on the "scope" field. It's identical to ScopeEQ.
func Scope(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldScope, v))
}

// ServerName applies equality check predicate on the "server_name" field. It's identical to ServerNameEQ.
func ServerName(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldServerName, v))
}

// State applies equality check predicate on the "state" field. It's identical to StateEQ.
func State(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldState, v))
}

// ResponseMode applies equality check predicate on the "response_mode" field. It's identical to ResponseModeEQ.
func ResponseMode(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldResponseMode, v))
}

// CodeChallengeEQ applies the EQ predicate on the "code_challenge" field.
func CodeChallengeEQ(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldCodeChallenge, v))
}

// CodeChallengeNEQ applies the NEQ predicate on the "code_challenge" field.
func CodeChallengeNEQ(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNEQ(FieldCodeChallenge, v))
}

// CodeChallengeIn applies the In predicate on the "code_challenge" field.
func CodeChallengeIn(vs ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldIn(FieldCodeChallenge, vs...))
}

// CodeChallengeNotIn applies the NotIn predicate on the "code_challenge" field.
func CodeChallengeNotIn(vs ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNotIn(FieldCodeChallenge, vs...))
}

// CodeChallengeGT applies the GT predicate on the "code_challenge" field.
func CodeChallengeGT(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGT(FieldCodeChallenge, v))
}

// CodeChallengeGTE applies the GTE predicate on the "code_challenge" field.
func CodeChallengeGTE(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGTE(FieldCodeChallenge, v))
}

// CodeChallengeLT applies the LT predicate on the "code_challenge" field.
func CodeChallengeLT(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLT(FieldCodeChallenge, v))
}

// CodeChallengeLTE applies the LTE predicate on the "code_challenge" field.
func CodeChallengeLTE(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLTE(FieldCodeChallenge, v))
}

// CodeChallengeContains applies the Contains predicate on the "code_challenge" field.
func CodeChallengeContains(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldContains(FieldCodeChallenge, v))
}

// CodeChallengeHasPrefix applies the HasPrefix predicate on the "code_challenge" field.
func CodeChallengeHasPrefix(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldHasPrefix(FieldCodeChallenge, v))
}

// CodeChallengeHasSuffix applies the HasSuffix predicate on the "code_challenge" field.
func CodeChallengeHasSuffix(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldHasSuffix(FieldCodeChallenge, v))
}

// CodeChallengeEqualFold applies the EqualFold predicate on the "code_challenge" field.
func CodeChallengeEqualFold(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEqualFold(FieldCodeChallenge, v))
}

// CodeChallengeContainsFold applies the ContainsFold predicate on the "code_challenge" field.
func CodeChallengeContainsFold(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldContainsFold(FieldCodeChallenge, v))
}

// CodeChallengeMethodEQ applies the EQ predicate on the "code_challenge_method" field.
func CodeChallengeMethodEQ(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldCodeChallengeMethod, v))
}

// CodeChallengeMethodNEQ applies the NEQ predicate on the "code_challenge_method" field.
func CodeChallengeMethodNEQ(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNEQ(FieldCodeChallengeMethod, v))
}

// CodeChallengeMethodIn applies the In predicate on the "code_challenge_method" field.
func CodeChallengeMethodIn(vs ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldIn(FieldCodeChallengeMethod, vs...))
}

// CodeChallengeMethodNotIn applies the NotIn predicate on the "code_challenge_method" field.
func CodeChallengeMethodNotIn(vs ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNotIn(FieldCodeChallengeMethod, vs...))
}

// CodeChallengeMethodGT applies the GT predicate on the "code_challenge_method" field.
func CodeChallengeMethodGT(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGT(FieldCodeChallengeMethod, v))
}

// CodeChallengeMethodGTE applies the GTE predicate on the "code_challenge_method" field.
func CodeChallengeMethodGTE(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGTE(FieldCodeChallengeMethod, v))
}

// CodeChallengeMethodLT applies the LT predicate on the "code_challenge_method" field.
func CodeChallengeMethodLT(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLT(FieldCodeChallengeMethod, v))
}

// CodeChallengeMethodLTE applies the LTE predicate on the "code_challenge_method" field.
func CodeChallengeMethodLTE(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLTE(FieldCodeChallengeMethod, v))
}

// CodeChallengeMethodContains applies the Contains predicate on the "code_challenge_method" field.
func CodeChallengeMethodContains(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldContains(FieldCodeChallengeMethod, v))
}

// CodeChallengeMethodHasPrefix applies the HasPrefix predicate on the "code_challenge_method" field.
func CodeChallengeMethodHasPrefix(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldHasPrefix(FieldCodeChallengeMethod, v))
}

// CodeChallengeMethodHasSuffix applies the HasSuffix predicate on the "code_challenge_method" field.
func CodeChallengeMethodHasSuffix(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldHasSuffix(FieldCodeChallengeMethod, v))
}

// CodeChallengeMethodEqualFold applies the EqualFold predicate on the "code_challenge_method" field.
func CodeChallengeMethodEqualFold(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEqualFold(FieldCodeChallengeMethod, v))
}

// CodeChallengeMethodContainsFold applies the ContainsFold predicate on the "code_challenge_method" field.
func CodeChallengeMethodContainsFold(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldContainsFold(FieldCodeChallengeMethod, v))
}

// ClientIDEQ applies the EQ predicate on the "client_id" field.
func ClientIDEQ(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldClientID, v))
}

// ClientIDNEQ applies the NEQ predicate on the "client_id" field.
func ClientIDNEQ(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNEQ(FieldClientID, v))
}

// ClientIDIn applies the In predicate on the "client_id" field.
func ClientIDIn(vs ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldIn(FieldClientID, vs...))
}

// ClientIDNotIn applies the NotIn predicate on the "client_id" field.
func ClientIDNotIn(vs ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNotIn(FieldClientID, vs...))
}

// ClientIDGT applies the GT predicate on the "client_id" field.
func ClientIDGT(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGT(FieldClientID, v))
}

// ClientIDGTE applies the GTE predicate on the "client_id" field.
func ClientIDGTE(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGTE(FieldClientID, v))
}

// ClientIDLT applies the LT predicate on the "client_id" field.
func ClientIDLT(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLT(FieldClientID, v))
}

// ClientIDLTE applies the LTE predicate on the "client_id" field.
func ClientIDLTE(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLTE(FieldClientID, v))
}

// ClientIDContains applies the Contains predicate on the "client_id" field.
func ClientIDContains(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldContains(FieldClientID, v))
}

// ClientIDHasPrefix applies the HasPrefix predicate on the "client_id" field.
func ClientIDHasPrefix(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldHasPrefix(FieldClientID, v))
}

// ClientIDHasSuffix applies the HasSuffix predicate on the "client_id" field.
func ClientIDHasSuffix(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldHasSuffix(FieldClientID, v))
}

// ClientIDEqualFold applies the EqualFold predicate on the "client_id" field.
func ClientIDEqualFold(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEqualFold(FieldClientID, v))
}

// ClientIDContainsFold applies the ContainsFold predicate on the "client_id" field.
func ClientIDContainsFold(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldContainsFold(FieldClientID, v))
}

// NonceEQ applies the EQ predicate on the "nonce" field.
func NonceEQ(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldNonce, v))
}

// NonceNEQ applies the NEQ predicate on the "nonce" field.
func NonceNEQ(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNEQ(FieldNonce, v))
}

// NonceIn applies the In predicate on the "nonce" field.
func NonceIn(vs ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldIn(FieldNonce, vs...))
}

// NonceNotIn applies the NotIn predicate on the "nonce" field.
func NonceNotIn(vs ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNotIn(FieldNonce, vs...))
}

// NonceGT applies the GT predicate on the "nonce" field.
func NonceGT(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGT(FieldNonce, v))
}

// NonceGTE applies the GTE predicate on the "nonce" field.
func NonceGTE(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGTE(FieldNonce, v))
}

// NonceLT applies the LT predicate on the "nonce" field.
func NonceLT(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLT(FieldNonce, v))
}

// NonceLTE applies the LTE predicate on the "nonce" field.
func NonceLTE(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLTE(FieldNonce, v))
}

// NonceContains applies the Contains predicate on the "nonce" field.
func NonceContains(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldContains(FieldNonce, v))
}

// NonceHasPrefix applies the HasPrefix predicate on the "nonce" field.
func NonceHasPrefix(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldHasPrefix(FieldNonce, v))
}

// NonceHasSuffix applies the HasSuffix predicate on the "nonce" field.
func NonceHasSuffix(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldHasSuffix(FieldNonce, v))
}

// NonceEqualFold applies the EqualFold predicate on the "nonce" field.
func NonceEqualFold(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEqualFold(FieldNonce, v))
}

// NonceContainsFold applies the ContainsFold predicate on the "nonce" field.
func NonceContainsFold(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldContainsFold(FieldNonce, v))
}

// RedirectURIEQ applies the EQ predicate on the "redirect_uri" field.
func RedirectURIEQ(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldRedirectURI, v))
}

// RedirectURINEQ applies the NEQ predicate on the "redirect_uri" field.
func RedirectURINEQ(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNEQ(FieldRedirectURI, v))
}

// RedirectURIIn applies the In predicate on the "redirect_uri" field.
func RedirectURIIn(vs ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldIn(FieldRedirectURI, vs...))
}

// RedirectURINotIn applies the NotIn predicate on the "redirect_uri" field.
func RedirectURINotIn(vs ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNotIn(FieldRedirectURI, vs...))
}

// RedirectURIGT applies the GT predicate on the "redirect_uri" field.
func RedirectURIGT(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGT(FieldRedirectURI, v))
}

// RedirectURIGTE applies the GTE predicate on the "redirect_uri" field.
func RedirectURIGTE(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGTE(FieldRedirectURI, v))
}

// RedirectURILT applies the LT predicate on the "redirect_uri" field.
func RedirectURILT(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLT(FieldRedirectURI, v))
}

// RedirectURILTE applies the LTE predicate on the "redirect_uri" field.
func RedirectURILTE(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLTE(FieldRedirectURI, v))
}

// RedirectURIContains applies the Contains predicate on the "redirect_uri" field.
func RedirectURIContains(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldContains(FieldRedirectURI, v))
}

// RedirectURIHasPrefix applies the HasPrefix predicate on the "redirect_uri" field.
func RedirectURIHasPrefix(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldHasPrefix(FieldRedirectURI, v))
}

// RedirectURIHasSuffix applies the HasSuffix predicate on the "redirect_uri" field.
func RedirectURIHasSuffix(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldHasSuffix(FieldRedirectURI, v))
}

// RedirectURIEqualFold applies the EqualFold predicate on the "redirect_uri" field.
func RedirectURIEqualFold(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEqualFold(FieldRedirectURI, v))
}

// RedirectURIContainsFold applies the ContainsFold predicate on the "redirect_uri" field.
func RedirectURIContainsFold(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldContainsFold(FieldRedirectURI, v))
}

// ResponseTypeEQ applies the EQ predicate on the "response_type" field.
func ResponseTypeEQ(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldResponseType, v))
}

// ResponseTypeNEQ applies the NEQ predicate on the "response_type" field.
func ResponseTypeNEQ(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNEQ(FieldResponseType, v))
}

// ResponseTypeIn applies the In predicate on the "response_type" field.
func ResponseTypeIn(vs ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldIn(FieldResponseType, vs...))
}

// ResponseTypeNotIn applies the NotIn predicate on the "response_type" field.
func ResponseTypeNotIn(vs ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNotIn(FieldResponseType, vs...))
}

// ResponseTypeGT applies the GT predicate on the "response_type" field.
func ResponseTypeGT(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGT(FieldResponseType, v))
}

// ResponseTypeGTE applies the GTE predicate on the "response_type" field.
func ResponseTypeGTE(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGTE(FieldResponseType, v))
}

// ResponseTypeLT applies the LT predicate on the "response_type" field.
func ResponseTypeLT(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLT(FieldResponseType, v))
}

// ResponseTypeLTE applies the LTE predicate on the "response_type" field.
func ResponseTypeLTE(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLTE(FieldResponseType, v))
}

// ResponseTypeContains applies the Contains predicate on the "response_type" field.
func ResponseTypeContains(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldContains(FieldResponseType, v))
}

// ResponseTypeHasPrefix applies the HasPrefix predicate on the "response_type" field.
func ResponseTypeHasPrefix(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldHasPrefix(FieldResponseType, v))
}

// ResponseTypeHasSuffix applies the HasSuffix predicate on the "response_type" field.
func ResponseTypeHasSuffix(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldHasSuffix(FieldResponseType, v))
}

// ResponseTypeEqualFold applies the EqualFold predicate on the "response_type" field.
func ResponseTypeEqualFold(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEqualFold(FieldResponseType, v))
}

// ResponseTypeContainsFold applies the ContainsFold predicate on the "response_type" field.
func ResponseTypeContainsFold(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldContainsFold(FieldResponseType, v))
}

// ScopeEQ applies the EQ predicate on the "scope" field.
func ScopeEQ(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldScope, v))
}

// ScopeNEQ applies the NEQ predicate on the "scope" field.
func ScopeNEQ(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNEQ(FieldScope, v))
}

// ScopeIn applies the In predicate on the "scope" field.
func ScopeIn(vs ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldIn(FieldScope, vs...))
}

// ScopeNotIn applies the NotIn predicate on the "scope" field.
func ScopeNotIn(vs ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNotIn(FieldScope, vs...))
}

// ScopeGT applies the GT predicate on the "scope" field.
func ScopeGT(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGT(FieldScope, v))
}

// ScopeGTE applies the GTE predicate on the "scope" field.
func ScopeGTE(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGTE(FieldScope, v))
}

// ScopeLT applies the LT predicate on the "scope" field.
func ScopeLT(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLT(FieldScope, v))
}

// ScopeLTE applies the LTE predicate on the "scope" field.
func ScopeLTE(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLTE(FieldScope, v))
}

// ScopeContains applies the Contains predicate on the "scope" field.
func ScopeContains(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldContains(FieldScope, v))
}

// ScopeHasPrefix applies the HasPrefix predicate on the "scope" field.
func ScopeHasPrefix(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldHasPrefix(FieldScope, v))
}

// ScopeHasSuffix applies the HasSuffix predicate on the "scope" field.
func ScopeHasSuffix(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldHasSuffix(FieldScope, v))
}

// ScopeEqualFold applies the EqualFold predicate on the "scope" field.
func ScopeEqualFold(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEqualFold(FieldScope, v))
}

// ScopeContainsFold applies the ContainsFold predicate on the "scope" field.
func ScopeContainsFold(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldContainsFold(FieldScope, v))
}

// ServerNameEQ applies the EQ predicate on the "server_name" field.
func ServerNameEQ(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldServerName, v))
}

// ServerNameNEQ applies the NEQ predicate on the "server_name" field.
func ServerNameNEQ(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNEQ(FieldServerName, v))
}

// ServerNameIn applies the In predicate on the "server_name" field.
func ServerNameIn(vs ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldIn(FieldServerName, vs...))
}

// ServerNameNotIn applies the NotIn predicate on the "server_name" field.
func ServerNameNotIn(vs ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNotIn(FieldServerName, vs...))
}

// ServerNameGT applies the GT predicate on the "server_name" field.
func ServerNameGT(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGT(FieldServerName, v))
}

// ServerNameGTE applies the GTE predicate on the "server_name" field.
func ServerNameGTE(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGTE(FieldServerName, v))
}

// ServerNameLT applies the LT predicate on the "server_name" field.
func ServerNameLT(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLT(FieldServerName, v))
}

// ServerNameLTE applies the LTE predicate on the "server_name" field.
func ServerNameLTE(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLTE(FieldServerName, v))
}

// ServerNameContains applies the Contains predicate on the "server_name" field.
func ServerNameContains(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldContains(FieldServerName, v))
}

// ServerNameHasPrefix applies the HasPrefix predicate on the "server_name" field.
func ServerNameHasPrefix(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldHasPrefix(FieldServerName, v))
}

// ServerNameHasSuffix applies the HasSuffix predicate on the "server_name" field.
func ServerNameHasSuffix(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldHasSuffix(FieldServerName, v))
}

// ServerNameEqualFold applies the EqualFold predicate on the "server_name" field.
func ServerNameEqualFold(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEqualFold(FieldServerName, v))
}

// ServerNameContainsFold applies the ContainsFold predicate on the "server_name" field.
func ServerNameContainsFold(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldContainsFold(FieldServerName, v))
}

// StateEQ applies the EQ predicate on the "state" field.
func StateEQ(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldState, v))
}

// StateNEQ applies the NEQ predicate on the "state" field.
func StateNEQ(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNEQ(FieldState, v))
}

// StateIn applies the In predicate on the "state" field.
func StateIn(vs ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldIn(FieldState, vs...))
}

// StateNotIn applies the NotIn predicate on the "state" field.
func StateNotIn(vs ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNotIn(FieldState, vs...))
}

// StateGT applies the GT predicate on the "state" field.
func StateGT(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGT(FieldState, v))
}

// StateGTE applies the GTE predicate on the "state" field.
func StateGTE(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGTE(FieldState, v))
}

// StateLT applies the LT predicate on the "state" field.
func StateLT(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLT(FieldState, v))
}

// StateLTE applies the LTE predicate on the "state" field.
func StateLTE(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLTE(FieldState, v))
}

// StateContains applies the Contains predicate on the "state" field.
func StateContains(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldContains(FieldState, v))
}

// StateHasPrefix applies the HasPrefix predicate on the "state" field.
func StateHasPrefix(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldHasPrefix(FieldState, v))
}

// StateHasSuffix applies the HasSuffix predicate on the "state" field.
func StateHasSuffix(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldHasSuffix(FieldState, v))
}

// StateEqualFold applies the EqualFold predicate on the "state" field.
func StateEqualFold(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEqualFold(FieldState, v))
}

// StateContainsFold applies the ContainsFold predicate on the "state" field.
func StateContainsFold(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldContainsFold(FieldState, v))
}

// ResponseModeEQ applies the EQ predicate on the "response_mode" field.
func ResponseModeEQ(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEQ(FieldResponseMode, v))
}

// ResponseModeNEQ applies the NEQ predicate on the "response_mode" field.
func ResponseModeNEQ(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNEQ(FieldResponseMode, v))
}

// ResponseModeIn applies the In predicate on the "response_mode" field.
func ResponseModeIn(vs ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldIn(FieldResponseMode, vs...))
}

// ResponseModeNotIn applies the NotIn predicate on the "response_mode" field.
func ResponseModeNotIn(vs ...string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldNotIn(FieldResponseMode, vs...))
}

// ResponseModeGT applies the GT predicate on the "response_mode" field.
func ResponseModeGT(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGT(FieldResponseMode, v))
}

// ResponseModeGTE applies the GTE predicate on the "response_mode" field.
func ResponseModeGTE(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldGTE(FieldResponseMode, v))
}

// ResponseModeLT applies the LT predicate on the "response_mode" field.
func ResponseModeLT(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLT(FieldResponseMode, v))
}

// ResponseModeLTE applies the LTE predicate on the "response_mode" field.
func ResponseModeLTE(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldLTE(FieldResponseMode, v))
}

// ResponseModeContains applies the Contains predicate on the "response_mode" field.
func ResponseModeContains(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldContains(FieldResponseMode, v))
}

// ResponseModeHasPrefix applies the HasPrefix predicate on the "response_mode" field.
func ResponseModeHasPrefix(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldHasPrefix(FieldResponseMode, v))
}

// ResponseModeHasSuffix applies the HasSuffix predicate on the "response_mode" field.
func ResponseModeHasSuffix(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldHasSuffix(FieldResponseMode, v))
}

// ResponseModeEqualFold applies the EqualFold predicate on the "response_mode" field.
func ResponseModeEqualFold(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldEqualFold(FieldResponseMode, v))
}

// ResponseModeContainsFold applies the ContainsFold predicate on the "response_mode" field.
func ResponseModeContainsFold(v string) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.FieldContainsFold(FieldResponseMode, v))
}

// HasSession applies the HasEdge predicate on the "session" edge.
func HasSession() predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, SessionTable, SessionColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasSessionWith applies the HasEdge predicate on the "session" edge with a given conditions (other predicates).
func HasSessionWith(preds ...predicate.Session) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(func(s *sql.Selector) {
		step := newSessionStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.AuthorizationPayload) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.AndPredicates(predicates...))
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.AuthorizationPayload) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.OrPredicates(predicates...))
}

// Not applies the not operator on the given predicate.
func Not(p predicate.AuthorizationPayload) predicate.AuthorizationPayload {
	return predicate.AuthorizationPayload(sql.NotPredicates(p))
}
