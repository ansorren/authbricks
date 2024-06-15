// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/cookiestore"
)

// CookieStoreCreate is the builder for creating a CookieStore entity.
type CookieStoreCreate struct {
	config
	mutation *CookieStoreMutation
	hooks    []Hook
}

// SetAuthKey sets the "auth_key" field.
func (csc *CookieStoreCreate) SetAuthKey(s string) *CookieStoreCreate {
	csc.mutation.SetAuthKey(s)
	return csc
}

// SetEncryptionKey sets the "encryption_key" field.
func (csc *CookieStoreCreate) SetEncryptionKey(s string) *CookieStoreCreate {
	csc.mutation.SetEncryptionKey(s)
	return csc
}

// SetID sets the "id" field.
func (csc *CookieStoreCreate) SetID(s string) *CookieStoreCreate {
	csc.mutation.SetID(s)
	return csc
}

// Mutation returns the CookieStoreMutation object of the builder.
func (csc *CookieStoreCreate) Mutation() *CookieStoreMutation {
	return csc.mutation
}

// Save creates the CookieStore in the database.
func (csc *CookieStoreCreate) Save(ctx context.Context) (*CookieStore, error) {
	return withHooks(ctx, csc.sqlSave, csc.mutation, csc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (csc *CookieStoreCreate) SaveX(ctx context.Context) *CookieStore {
	v, err := csc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (csc *CookieStoreCreate) Exec(ctx context.Context) error {
	_, err := csc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (csc *CookieStoreCreate) ExecX(ctx context.Context) {
	if err := csc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (csc *CookieStoreCreate) check() error {
	if _, ok := csc.mutation.AuthKey(); !ok {
		return &ValidationError{Name: "auth_key", err: errors.New(`ent: missing required field "CookieStore.auth_key"`)}
	}
	if v, ok := csc.mutation.AuthKey(); ok {
		if err := cookiestore.AuthKeyValidator(v); err != nil {
			return &ValidationError{Name: "auth_key", err: fmt.Errorf(`ent: validator failed for field "CookieStore.auth_key": %w`, err)}
		}
	}
	if _, ok := csc.mutation.EncryptionKey(); !ok {
		return &ValidationError{Name: "encryption_key", err: errors.New(`ent: missing required field "CookieStore.encryption_key"`)}
	}
	if v, ok := csc.mutation.EncryptionKey(); ok {
		if err := cookiestore.EncryptionKeyValidator(v); err != nil {
			return &ValidationError{Name: "encryption_key", err: fmt.Errorf(`ent: validator failed for field "CookieStore.encryption_key": %w`, err)}
		}
	}
	if v, ok := csc.mutation.ID(); ok {
		if err := cookiestore.IDValidator(v); err != nil {
			return &ValidationError{Name: "id", err: fmt.Errorf(`ent: validator failed for field "CookieStore.id": %w`, err)}
		}
	}
	return nil
}

func (csc *CookieStoreCreate) sqlSave(ctx context.Context) (*CookieStore, error) {
	if err := csc.check(); err != nil {
		return nil, err
	}
	_node, _spec := csc.createSpec()
	if err := sqlgraph.CreateNode(ctx, csc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(string); ok {
			_node.ID = id
		} else {
			return nil, fmt.Errorf("unexpected CookieStore.ID type: %T", _spec.ID.Value)
		}
	}
	csc.mutation.id = &_node.ID
	csc.mutation.done = true
	return _node, nil
}

func (csc *CookieStoreCreate) createSpec() (*CookieStore, *sqlgraph.CreateSpec) {
	var (
		_node = &CookieStore{config: csc.config}
		_spec = sqlgraph.NewCreateSpec(cookiestore.Table, sqlgraph.NewFieldSpec(cookiestore.FieldID, field.TypeString))
	)
	if id, ok := csc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if value, ok := csc.mutation.AuthKey(); ok {
		_spec.SetField(cookiestore.FieldAuthKey, field.TypeString, value)
		_node.AuthKey = value
	}
	if value, ok := csc.mutation.EncryptionKey(); ok {
		_spec.SetField(cookiestore.FieldEncryptionKey, field.TypeString, value)
		_node.EncryptionKey = value
	}
	return _node, _spec
}

// CookieStoreCreateBulk is the builder for creating many CookieStore entities in bulk.
type CookieStoreCreateBulk struct {
	config
	err      error
	builders []*CookieStoreCreate
}

// Save creates the CookieStore entities in the database.
func (cscb *CookieStoreCreateBulk) Save(ctx context.Context) ([]*CookieStore, error) {
	if cscb.err != nil {
		return nil, cscb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(cscb.builders))
	nodes := make([]*CookieStore, len(cscb.builders))
	mutators := make([]Mutator, len(cscb.builders))
	for i := range cscb.builders {
		func(i int, root context.Context) {
			builder := cscb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*CookieStoreMutation)
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
					_, err = mutators[i+1].Mutate(root, cscb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, cscb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, cscb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (cscb *CookieStoreCreateBulk) SaveX(ctx context.Context) []*CookieStore {
	v, err := cscb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (cscb *CookieStoreCreateBulk) Exec(ctx context.Context) error {
	_, err := cscb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (cscb *CookieStoreCreateBulk) ExecX(ctx context.Context) {
	if err := cscb.Exec(ctx); err != nil {
		panic(err)
	}
}