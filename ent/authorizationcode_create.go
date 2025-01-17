// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/authorizationcode"
)

// AuthorizationCodeCreate is the builder for creating a AuthorizationCode entity.
type AuthorizationCodeCreate struct {
	config
	mutation *AuthorizationCodeMutation
	hooks    []Hook
}

// SetApplication sets the "application" field.
func (acc *AuthorizationCodeCreate) SetApplication(s string) *AuthorizationCodeCreate {
	acc.mutation.SetApplication(s)
	return acc
}

// SetCodeChallenge sets the "code_challenge" field.
func (acc *AuthorizationCodeCreate) SetCodeChallenge(s string) *AuthorizationCodeCreate {
	acc.mutation.SetCodeChallenge(s)
	return acc
}

// SetCodeChallengeMethod sets the "code_challenge_method" field.
func (acc *AuthorizationCodeCreate) SetCodeChallengeMethod(s string) *AuthorizationCodeCreate {
	acc.mutation.SetCodeChallengeMethod(s)
	return acc
}

// SetCreatedAt sets the "created_at" field.
func (acc *AuthorizationCodeCreate) SetCreatedAt(t time.Time) *AuthorizationCodeCreate {
	acc.mutation.SetCreatedAt(t)
	return acc
}

// SetAuthTime sets the "auth_time" field.
func (acc *AuthorizationCodeCreate) SetAuthTime(t time.Time) *AuthorizationCodeCreate {
	acc.mutation.SetAuthTime(t)
	return acc
}

// SetRedirectURI sets the "redirect_uri" field.
func (acc *AuthorizationCodeCreate) SetRedirectURI(s string) *AuthorizationCodeCreate {
	acc.mutation.SetRedirectURI(s)
	return acc
}

// SetNonce sets the "nonce" field.
func (acc *AuthorizationCodeCreate) SetNonce(s string) *AuthorizationCodeCreate {
	acc.mutation.SetNonce(s)
	return acc
}

// SetService sets the "service" field.
func (acc *AuthorizationCodeCreate) SetService(s string) *AuthorizationCodeCreate {
	acc.mutation.SetService(s)
	return acc
}

// SetState sets the "state" field.
func (acc *AuthorizationCodeCreate) SetState(s string) *AuthorizationCodeCreate {
	acc.mutation.SetState(s)
	return acc
}

// SetSubject sets the "subject" field.
func (acc *AuthorizationCodeCreate) SetSubject(s string) *AuthorizationCodeCreate {
	acc.mutation.SetSubject(s)
	return acc
}

// SetGrantedScopes sets the "granted_scopes" field.
func (acc *AuthorizationCodeCreate) SetGrantedScopes(s string) *AuthorizationCodeCreate {
	acc.mutation.SetGrantedScopes(s)
	return acc
}

// SetID sets the "id" field.
func (acc *AuthorizationCodeCreate) SetID(s string) *AuthorizationCodeCreate {
	acc.mutation.SetID(s)
	return acc
}

// Mutation returns the AuthorizationCodeMutation object of the builder.
func (acc *AuthorizationCodeCreate) Mutation() *AuthorizationCodeMutation {
	return acc.mutation
}

// Save creates the AuthorizationCode in the database.
func (acc *AuthorizationCodeCreate) Save(ctx context.Context) (*AuthorizationCode, error) {
	return withHooks(ctx, acc.sqlSave, acc.mutation, acc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (acc *AuthorizationCodeCreate) SaveX(ctx context.Context) *AuthorizationCode {
	v, err := acc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (acc *AuthorizationCodeCreate) Exec(ctx context.Context) error {
	_, err := acc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (acc *AuthorizationCodeCreate) ExecX(ctx context.Context) {
	if err := acc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (acc *AuthorizationCodeCreate) check() error {
	if _, ok := acc.mutation.Application(); !ok {
		return &ValidationError{Name: "application", err: errors.New(`ent: missing required field "AuthorizationCode.application"`)}
	}
	if _, ok := acc.mutation.CodeChallenge(); !ok {
		return &ValidationError{Name: "code_challenge", err: errors.New(`ent: missing required field "AuthorizationCode.code_challenge"`)}
	}
	if _, ok := acc.mutation.CodeChallengeMethod(); !ok {
		return &ValidationError{Name: "code_challenge_method", err: errors.New(`ent: missing required field "AuthorizationCode.code_challenge_method"`)}
	}
	if _, ok := acc.mutation.CreatedAt(); !ok {
		return &ValidationError{Name: "created_at", err: errors.New(`ent: missing required field "AuthorizationCode.created_at"`)}
	}
	if _, ok := acc.mutation.AuthTime(); !ok {
		return &ValidationError{Name: "auth_time", err: errors.New(`ent: missing required field "AuthorizationCode.auth_time"`)}
	}
	if _, ok := acc.mutation.RedirectURI(); !ok {
		return &ValidationError{Name: "redirect_uri", err: errors.New(`ent: missing required field "AuthorizationCode.redirect_uri"`)}
	}
	if _, ok := acc.mutation.Nonce(); !ok {
		return &ValidationError{Name: "nonce", err: errors.New(`ent: missing required field "AuthorizationCode.nonce"`)}
	}
	if _, ok := acc.mutation.Service(); !ok {
		return &ValidationError{Name: "service", err: errors.New(`ent: missing required field "AuthorizationCode.service"`)}
	}
	if _, ok := acc.mutation.State(); !ok {
		return &ValidationError{Name: "state", err: errors.New(`ent: missing required field "AuthorizationCode.state"`)}
	}
	if _, ok := acc.mutation.Subject(); !ok {
		return &ValidationError{Name: "subject", err: errors.New(`ent: missing required field "AuthorizationCode.subject"`)}
	}
	if _, ok := acc.mutation.GrantedScopes(); !ok {
		return &ValidationError{Name: "granted_scopes", err: errors.New(`ent: missing required field "AuthorizationCode.granted_scopes"`)}
	}
	if v, ok := acc.mutation.ID(); ok {
		if err := authorizationcode.IDValidator(v); err != nil {
			return &ValidationError{Name: "id", err: fmt.Errorf(`ent: validator failed for field "AuthorizationCode.id": %w`, err)}
		}
	}
	return nil
}

func (acc *AuthorizationCodeCreate) sqlSave(ctx context.Context) (*AuthorizationCode, error) {
	if err := acc.check(); err != nil {
		return nil, err
	}
	_node, _spec := acc.createSpec()
	if err := sqlgraph.CreateNode(ctx, acc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(string); ok {
			_node.ID = id
		} else {
			return nil, fmt.Errorf("unexpected AuthorizationCode.ID type: %T", _spec.ID.Value)
		}
	}
	acc.mutation.id = &_node.ID
	acc.mutation.done = true
	return _node, nil
}

func (acc *AuthorizationCodeCreate) createSpec() (*AuthorizationCode, *sqlgraph.CreateSpec) {
	var (
		_node = &AuthorizationCode{config: acc.config}
		_spec = sqlgraph.NewCreateSpec(authorizationcode.Table, sqlgraph.NewFieldSpec(authorizationcode.FieldID, field.TypeString))
	)
	if id, ok := acc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if value, ok := acc.mutation.Application(); ok {
		_spec.SetField(authorizationcode.FieldApplication, field.TypeString, value)
		_node.Application = value
	}
	if value, ok := acc.mutation.CodeChallenge(); ok {
		_spec.SetField(authorizationcode.FieldCodeChallenge, field.TypeString, value)
		_node.CodeChallenge = value
	}
	if value, ok := acc.mutation.CodeChallengeMethod(); ok {
		_spec.SetField(authorizationcode.FieldCodeChallengeMethod, field.TypeString, value)
		_node.CodeChallengeMethod = value
	}
	if value, ok := acc.mutation.CreatedAt(); ok {
		_spec.SetField(authorizationcode.FieldCreatedAt, field.TypeTime, value)
		_node.CreatedAt = value
	}
	if value, ok := acc.mutation.AuthTime(); ok {
		_spec.SetField(authorizationcode.FieldAuthTime, field.TypeTime, value)
		_node.AuthTime = value
	}
	if value, ok := acc.mutation.RedirectURI(); ok {
		_spec.SetField(authorizationcode.FieldRedirectURI, field.TypeString, value)
		_node.RedirectURI = value
	}
	if value, ok := acc.mutation.Nonce(); ok {
		_spec.SetField(authorizationcode.FieldNonce, field.TypeString, value)
		_node.Nonce = value
	}
	if value, ok := acc.mutation.Service(); ok {
		_spec.SetField(authorizationcode.FieldService, field.TypeString, value)
		_node.Service = value
	}
	if value, ok := acc.mutation.State(); ok {
		_spec.SetField(authorizationcode.FieldState, field.TypeString, value)
		_node.State = value
	}
	if value, ok := acc.mutation.Subject(); ok {
		_spec.SetField(authorizationcode.FieldSubject, field.TypeString, value)
		_node.Subject = value
	}
	if value, ok := acc.mutation.GrantedScopes(); ok {
		_spec.SetField(authorizationcode.FieldGrantedScopes, field.TypeString, value)
		_node.GrantedScopes = value
	}
	return _node, _spec
}

// AuthorizationCodeCreateBulk is the builder for creating many AuthorizationCode entities in bulk.
type AuthorizationCodeCreateBulk struct {
	config
	err      error
	builders []*AuthorizationCodeCreate
}

// Save creates the AuthorizationCode entities in the database.
func (accb *AuthorizationCodeCreateBulk) Save(ctx context.Context) ([]*AuthorizationCode, error) {
	if accb.err != nil {
		return nil, accb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(accb.builders))
	nodes := make([]*AuthorizationCode, len(accb.builders))
	mutators := make([]Mutator, len(accb.builders))
	for i := range accb.builders {
		func(i int, root context.Context) {
			builder := accb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*AuthorizationCodeMutation)
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
					_, err = mutators[i+1].Mutate(root, accb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, accb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, accb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (accb *AuthorizationCodeCreateBulk) SaveX(ctx context.Context) []*AuthorizationCode {
	v, err := accb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (accb *AuthorizationCodeCreateBulk) Exec(ctx context.Context) error {
	_, err := accb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (accb *AuthorizationCodeCreateBulk) ExecX(ctx context.Context) {
	if err := accb.Exec(ctx); err != nil {
		panic(err)
	}
}
