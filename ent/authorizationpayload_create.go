// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/authorizationpayload"
	"go.authbricks.com/bricks/ent/session"
)

// AuthorizationPayloadCreate is the builder for creating a AuthorizationPayload entity.
type AuthorizationPayloadCreate struct {
	config
	mutation *AuthorizationPayloadMutation
	hooks    []Hook
}

// SetCodeChallenge sets the "code_challenge" field.
func (apc *AuthorizationPayloadCreate) SetCodeChallenge(s string) *AuthorizationPayloadCreate {
	apc.mutation.SetCodeChallenge(s)
	return apc
}

// SetCodeChallengeMethod sets the "code_challenge_method" field.
func (apc *AuthorizationPayloadCreate) SetCodeChallengeMethod(s string) *AuthorizationPayloadCreate {
	apc.mutation.SetCodeChallengeMethod(s)
	return apc
}

// SetClientID sets the "client_id" field.
func (apc *AuthorizationPayloadCreate) SetClientID(s string) *AuthorizationPayloadCreate {
	apc.mutation.SetClientID(s)
	return apc
}

// SetNonce sets the "nonce" field.
func (apc *AuthorizationPayloadCreate) SetNonce(s string) *AuthorizationPayloadCreate {
	apc.mutation.SetNonce(s)
	return apc
}

// SetRedirectURI sets the "redirect_uri" field.
func (apc *AuthorizationPayloadCreate) SetRedirectURI(s string) *AuthorizationPayloadCreate {
	apc.mutation.SetRedirectURI(s)
	return apc
}

// SetResponseType sets the "response_type" field.
func (apc *AuthorizationPayloadCreate) SetResponseType(s string) *AuthorizationPayloadCreate {
	apc.mutation.SetResponseType(s)
	return apc
}

// SetScope sets the "scope" field.
func (apc *AuthorizationPayloadCreate) SetScope(s string) *AuthorizationPayloadCreate {
	apc.mutation.SetScope(s)
	return apc
}

// SetServerName sets the "server_name" field.
func (apc *AuthorizationPayloadCreate) SetServerName(s string) *AuthorizationPayloadCreate {
	apc.mutation.SetServerName(s)
	return apc
}

// SetState sets the "state" field.
func (apc *AuthorizationPayloadCreate) SetState(s string) *AuthorizationPayloadCreate {
	apc.mutation.SetState(s)
	return apc
}

// SetResponseMode sets the "response_mode" field.
func (apc *AuthorizationPayloadCreate) SetResponseMode(s string) *AuthorizationPayloadCreate {
	apc.mutation.SetResponseMode(s)
	return apc
}

// SetID sets the "id" field.
func (apc *AuthorizationPayloadCreate) SetID(s string) *AuthorizationPayloadCreate {
	apc.mutation.SetID(s)
	return apc
}

// SetSessionID sets the "session" edge to the Session entity by ID.
func (apc *AuthorizationPayloadCreate) SetSessionID(id string) *AuthorizationPayloadCreate {
	apc.mutation.SetSessionID(id)
	return apc
}

// SetNillableSessionID sets the "session" edge to the Session entity by ID if the given value is not nil.
func (apc *AuthorizationPayloadCreate) SetNillableSessionID(id *string) *AuthorizationPayloadCreate {
	if id != nil {
		apc = apc.SetSessionID(*id)
	}
	return apc
}

// SetSession sets the "session" edge to the Session entity.
func (apc *AuthorizationPayloadCreate) SetSession(s *Session) *AuthorizationPayloadCreate {
	return apc.SetSessionID(s.ID)
}

// Mutation returns the AuthorizationPayloadMutation object of the builder.
func (apc *AuthorizationPayloadCreate) Mutation() *AuthorizationPayloadMutation {
	return apc.mutation
}

// Save creates the AuthorizationPayload in the database.
func (apc *AuthorizationPayloadCreate) Save(ctx context.Context) (*AuthorizationPayload, error) {
	return withHooks(ctx, apc.sqlSave, apc.mutation, apc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (apc *AuthorizationPayloadCreate) SaveX(ctx context.Context) *AuthorizationPayload {
	v, err := apc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (apc *AuthorizationPayloadCreate) Exec(ctx context.Context) error {
	_, err := apc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (apc *AuthorizationPayloadCreate) ExecX(ctx context.Context) {
	if err := apc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (apc *AuthorizationPayloadCreate) check() error {
	if _, ok := apc.mutation.CodeChallenge(); !ok {
		return &ValidationError{Name: "code_challenge", err: errors.New(`ent: missing required field "AuthorizationPayload.code_challenge"`)}
	}
	if _, ok := apc.mutation.CodeChallengeMethod(); !ok {
		return &ValidationError{Name: "code_challenge_method", err: errors.New(`ent: missing required field "AuthorizationPayload.code_challenge_method"`)}
	}
	if _, ok := apc.mutation.ClientID(); !ok {
		return &ValidationError{Name: "client_id", err: errors.New(`ent: missing required field "AuthorizationPayload.client_id"`)}
	}
	if _, ok := apc.mutation.Nonce(); !ok {
		return &ValidationError{Name: "nonce", err: errors.New(`ent: missing required field "AuthorizationPayload.nonce"`)}
	}
	if _, ok := apc.mutation.RedirectURI(); !ok {
		return &ValidationError{Name: "redirect_uri", err: errors.New(`ent: missing required field "AuthorizationPayload.redirect_uri"`)}
	}
	if _, ok := apc.mutation.ResponseType(); !ok {
		return &ValidationError{Name: "response_type", err: errors.New(`ent: missing required field "AuthorizationPayload.response_type"`)}
	}
	if _, ok := apc.mutation.Scope(); !ok {
		return &ValidationError{Name: "scope", err: errors.New(`ent: missing required field "AuthorizationPayload.scope"`)}
	}
	if _, ok := apc.mutation.ServerName(); !ok {
		return &ValidationError{Name: "server_name", err: errors.New(`ent: missing required field "AuthorizationPayload.server_name"`)}
	}
	if _, ok := apc.mutation.State(); !ok {
		return &ValidationError{Name: "state", err: errors.New(`ent: missing required field "AuthorizationPayload.state"`)}
	}
	if _, ok := apc.mutation.ResponseMode(); !ok {
		return &ValidationError{Name: "response_mode", err: errors.New(`ent: missing required field "AuthorizationPayload.response_mode"`)}
	}
	if v, ok := apc.mutation.ID(); ok {
		if err := authorizationpayload.IDValidator(v); err != nil {
			return &ValidationError{Name: "id", err: fmt.Errorf(`ent: validator failed for field "AuthorizationPayload.id": %w`, err)}
		}
	}
	return nil
}

func (apc *AuthorizationPayloadCreate) sqlSave(ctx context.Context) (*AuthorizationPayload, error) {
	if err := apc.check(); err != nil {
		return nil, err
	}
	_node, _spec := apc.createSpec()
	if err := sqlgraph.CreateNode(ctx, apc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(string); ok {
			_node.ID = id
		} else {
			return nil, fmt.Errorf("unexpected AuthorizationPayload.ID type: %T", _spec.ID.Value)
		}
	}
	apc.mutation.id = &_node.ID
	apc.mutation.done = true
	return _node, nil
}

func (apc *AuthorizationPayloadCreate) createSpec() (*AuthorizationPayload, *sqlgraph.CreateSpec) {
	var (
		_node = &AuthorizationPayload{config: apc.config}
		_spec = sqlgraph.NewCreateSpec(authorizationpayload.Table, sqlgraph.NewFieldSpec(authorizationpayload.FieldID, field.TypeString))
	)
	if id, ok := apc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if value, ok := apc.mutation.CodeChallenge(); ok {
		_spec.SetField(authorizationpayload.FieldCodeChallenge, field.TypeString, value)
		_node.CodeChallenge = value
	}
	if value, ok := apc.mutation.CodeChallengeMethod(); ok {
		_spec.SetField(authorizationpayload.FieldCodeChallengeMethod, field.TypeString, value)
		_node.CodeChallengeMethod = value
	}
	if value, ok := apc.mutation.ClientID(); ok {
		_spec.SetField(authorizationpayload.FieldClientID, field.TypeString, value)
		_node.ClientID = value
	}
	if value, ok := apc.mutation.Nonce(); ok {
		_spec.SetField(authorizationpayload.FieldNonce, field.TypeString, value)
		_node.Nonce = value
	}
	if value, ok := apc.mutation.RedirectURI(); ok {
		_spec.SetField(authorizationpayload.FieldRedirectURI, field.TypeString, value)
		_node.RedirectURI = value
	}
	if value, ok := apc.mutation.ResponseType(); ok {
		_spec.SetField(authorizationpayload.FieldResponseType, field.TypeString, value)
		_node.ResponseType = value
	}
	if value, ok := apc.mutation.Scope(); ok {
		_spec.SetField(authorizationpayload.FieldScope, field.TypeString, value)
		_node.Scope = value
	}
	if value, ok := apc.mutation.ServerName(); ok {
		_spec.SetField(authorizationpayload.FieldServerName, field.TypeString, value)
		_node.ServerName = value
	}
	if value, ok := apc.mutation.State(); ok {
		_spec.SetField(authorizationpayload.FieldState, field.TypeString, value)
		_node.State = value
	}
	if value, ok := apc.mutation.ResponseMode(); ok {
		_spec.SetField(authorizationpayload.FieldResponseMode, field.TypeString, value)
		_node.ResponseMode = value
	}
	if nodes := apc.mutation.SessionIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   authorizationpayload.SessionTable,
			Columns: []string{authorizationpayload.SessionColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(session.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.session_authorization_payload = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// AuthorizationPayloadCreateBulk is the builder for creating many AuthorizationPayload entities in bulk.
type AuthorizationPayloadCreateBulk struct {
	config
	err      error
	builders []*AuthorizationPayloadCreate
}

// Save creates the AuthorizationPayload entities in the database.
func (apcb *AuthorizationPayloadCreateBulk) Save(ctx context.Context) ([]*AuthorizationPayload, error) {
	if apcb.err != nil {
		return nil, apcb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(apcb.builders))
	nodes := make([]*AuthorizationPayload, len(apcb.builders))
	mutators := make([]Mutator, len(apcb.builders))
	for i := range apcb.builders {
		func(i int, root context.Context) {
			builder := apcb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*AuthorizationPayloadMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, apcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, apcb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, apcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (apcb *AuthorizationPayloadCreateBulk) SaveX(ctx context.Context) []*AuthorizationPayload {
	v, err := apcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (apcb *AuthorizationPayloadCreateBulk) Exec(ctx context.Context) error {
	_, err := apcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (apcb *AuthorizationPayloadCreateBulk) ExecX(ctx context.Context) {
	if err := apcb.Exec(ctx); err != nil {
		panic(err)
	}
}