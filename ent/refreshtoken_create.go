// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/refreshtoken"
)

// RefreshTokenCreate is the builder for creating a RefreshToken entity.
type RefreshTokenCreate struct {
	config
	mutation *RefreshTokenMutation
	hooks    []Hook
}

// SetClientName sets the "client_name" field.
func (rtc *RefreshTokenCreate) SetClientName(s string) *RefreshTokenCreate {
	rtc.mutation.SetClientName(s)
	return rtc
}

// SetServerName sets the "server_name" field.
func (rtc *RefreshTokenCreate) SetServerName(s string) *RefreshTokenCreate {
	rtc.mutation.SetServerName(s)
	return rtc
}

// SetScopes sets the "scopes" field.
func (rtc *RefreshTokenCreate) SetScopes(s string) *RefreshTokenCreate {
	rtc.mutation.SetScopes(s)
	return rtc
}

// SetCreatedAt sets the "created_at" field.
func (rtc *RefreshTokenCreate) SetCreatedAt(i int64) *RefreshTokenCreate {
	rtc.mutation.SetCreatedAt(i)
	return rtc
}

// SetAccessTokenID sets the "access_token_id" field.
func (rtc *RefreshTokenCreate) SetAccessTokenID(s string) *RefreshTokenCreate {
	rtc.mutation.SetAccessTokenID(s)
	return rtc
}

// SetLifetime sets the "lifetime" field.
func (rtc *RefreshTokenCreate) SetLifetime(i int64) *RefreshTokenCreate {
	rtc.mutation.SetLifetime(i)
	return rtc
}

// SetSubject sets the "subject" field.
func (rtc *RefreshTokenCreate) SetSubject(s string) *RefreshTokenCreate {
	rtc.mutation.SetSubject(s)
	return rtc
}

// SetKeyID sets the "key_id" field.
func (rtc *RefreshTokenCreate) SetKeyID(s string) *RefreshTokenCreate {
	rtc.mutation.SetKeyID(s)
	return rtc
}

// SetAuthTime sets the "auth_time" field.
func (rtc *RefreshTokenCreate) SetAuthTime(t time.Time) *RefreshTokenCreate {
	rtc.mutation.SetAuthTime(t)
	return rtc
}

// SetID sets the "id" field.
func (rtc *RefreshTokenCreate) SetID(s string) *RefreshTokenCreate {
	rtc.mutation.SetID(s)
	return rtc
}

// Mutation returns the RefreshTokenMutation object of the builder.
func (rtc *RefreshTokenCreate) Mutation() *RefreshTokenMutation {
	return rtc.mutation
}

// Save creates the RefreshToken in the database.
func (rtc *RefreshTokenCreate) Save(ctx context.Context) (*RefreshToken, error) {
	return withHooks(ctx, rtc.sqlSave, rtc.mutation, rtc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (rtc *RefreshTokenCreate) SaveX(ctx context.Context) *RefreshToken {
	v, err := rtc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (rtc *RefreshTokenCreate) Exec(ctx context.Context) error {
	_, err := rtc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (rtc *RefreshTokenCreate) ExecX(ctx context.Context) {
	if err := rtc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (rtc *RefreshTokenCreate) check() error {
	if _, ok := rtc.mutation.ClientName(); !ok {
		return &ValidationError{Name: "client_name", err: errors.New(`ent: missing required field "RefreshToken.client_name"`)}
	}
	if _, ok := rtc.mutation.ServerName(); !ok {
		return &ValidationError{Name: "server_name", err: errors.New(`ent: missing required field "RefreshToken.server_name"`)}
	}
	if _, ok := rtc.mutation.Scopes(); !ok {
		return &ValidationError{Name: "scopes", err: errors.New(`ent: missing required field "RefreshToken.scopes"`)}
	}
	if _, ok := rtc.mutation.CreatedAt(); !ok {
		return &ValidationError{Name: "created_at", err: errors.New(`ent: missing required field "RefreshToken.created_at"`)}
	}
	if v, ok := rtc.mutation.CreatedAt(); ok {
		if err := refreshtoken.CreatedAtValidator(v); err != nil {
			return &ValidationError{Name: "created_at", err: fmt.Errorf(`ent: validator failed for field "RefreshToken.created_at": %w`, err)}
		}
	}
	if _, ok := rtc.mutation.AccessTokenID(); !ok {
		return &ValidationError{Name: "access_token_id", err: errors.New(`ent: missing required field "RefreshToken.access_token_id"`)}
	}
	if _, ok := rtc.mutation.Lifetime(); !ok {
		return &ValidationError{Name: "lifetime", err: errors.New(`ent: missing required field "RefreshToken.lifetime"`)}
	}
	if v, ok := rtc.mutation.Lifetime(); ok {
		if err := refreshtoken.LifetimeValidator(v); err != nil {
			return &ValidationError{Name: "lifetime", err: fmt.Errorf(`ent: validator failed for field "RefreshToken.lifetime": %w`, err)}
		}
	}
	if _, ok := rtc.mutation.Subject(); !ok {
		return &ValidationError{Name: "subject", err: errors.New(`ent: missing required field "RefreshToken.subject"`)}
	}
	if _, ok := rtc.mutation.KeyID(); !ok {
		return &ValidationError{Name: "key_id", err: errors.New(`ent: missing required field "RefreshToken.key_id"`)}
	}
	if _, ok := rtc.mutation.AuthTime(); !ok {
		return &ValidationError{Name: "auth_time", err: errors.New(`ent: missing required field "RefreshToken.auth_time"`)}
	}
	if v, ok := rtc.mutation.ID(); ok {
		if err := refreshtoken.IDValidator(v); err != nil {
			return &ValidationError{Name: "id", err: fmt.Errorf(`ent: validator failed for field "RefreshToken.id": %w`, err)}
		}
	}
	return nil
}

func (rtc *RefreshTokenCreate) sqlSave(ctx context.Context) (*RefreshToken, error) {
	if err := rtc.check(); err != nil {
		return nil, err
	}
	_node, _spec := rtc.createSpec()
	if err := sqlgraph.CreateNode(ctx, rtc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(string); ok {
			_node.ID = id
		} else {
			return nil, fmt.Errorf("unexpected RefreshToken.ID type: %T", _spec.ID.Value)
		}
	}
	rtc.mutation.id = &_node.ID
	rtc.mutation.done = true
	return _node, nil
}

func (rtc *RefreshTokenCreate) createSpec() (*RefreshToken, *sqlgraph.CreateSpec) {
	var (
		_node = &RefreshToken{config: rtc.config}
		_spec = sqlgraph.NewCreateSpec(refreshtoken.Table, sqlgraph.NewFieldSpec(refreshtoken.FieldID, field.TypeString))
	)
	if id, ok := rtc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if value, ok := rtc.mutation.ClientName(); ok {
		_spec.SetField(refreshtoken.FieldClientName, field.TypeString, value)
		_node.ClientName = value
	}
	if value, ok := rtc.mutation.ServerName(); ok {
		_spec.SetField(refreshtoken.FieldServerName, field.TypeString, value)
		_node.ServerName = value
	}
	if value, ok := rtc.mutation.Scopes(); ok {
		_spec.SetField(refreshtoken.FieldScopes, field.TypeString, value)
		_node.Scopes = value
	}
	if value, ok := rtc.mutation.CreatedAt(); ok {
		_spec.SetField(refreshtoken.FieldCreatedAt, field.TypeInt64, value)
		_node.CreatedAt = value
	}
	if value, ok := rtc.mutation.AccessTokenID(); ok {
		_spec.SetField(refreshtoken.FieldAccessTokenID, field.TypeString, value)
		_node.AccessTokenID = value
	}
	if value, ok := rtc.mutation.Lifetime(); ok {
		_spec.SetField(refreshtoken.FieldLifetime, field.TypeInt64, value)
		_node.Lifetime = value
	}
	if value, ok := rtc.mutation.Subject(); ok {
		_spec.SetField(refreshtoken.FieldSubject, field.TypeString, value)
		_node.Subject = value
	}
	if value, ok := rtc.mutation.KeyID(); ok {
		_spec.SetField(refreshtoken.FieldKeyID, field.TypeString, value)
		_node.KeyID = value
	}
	if value, ok := rtc.mutation.AuthTime(); ok {
		_spec.SetField(refreshtoken.FieldAuthTime, field.TypeTime, value)
		_node.AuthTime = value
	}
	return _node, _spec
}

// RefreshTokenCreateBulk is the builder for creating many RefreshToken entities in bulk.
type RefreshTokenCreateBulk struct {
	config
	err      error
	builders []*RefreshTokenCreate
}

// Save creates the RefreshToken entities in the database.
func (rtcb *RefreshTokenCreateBulk) Save(ctx context.Context) ([]*RefreshToken, error) {
	if rtcb.err != nil {
		return nil, rtcb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(rtcb.builders))
	nodes := make([]*RefreshToken, len(rtcb.builders))
	mutators := make([]Mutator, len(rtcb.builders))
	for i := range rtcb.builders {
		func(i int, root context.Context) {
			builder := rtcb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*RefreshTokenMutation)
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
					_, err = mutators[i+1].Mutate(root, rtcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, rtcb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, rtcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (rtcb *RefreshTokenCreateBulk) SaveX(ctx context.Context) []*RefreshToken {
	v, err := rtcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (rtcb *RefreshTokenCreateBulk) Exec(ctx context.Context) error {
	_, err := rtcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (rtcb *RefreshTokenCreateBulk) ExecX(ctx context.Context) {
	if err := rtcb.Exec(ctx); err != nil {
		panic(err)
	}
}