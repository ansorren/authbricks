// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/keyset"
	"go.authbricks.com/bricks/ent/signingkey"
)

// SigningKeyCreate is the builder for creating a SigningKey entity.
type SigningKeyCreate struct {
	config
	mutation *SigningKeyMutation
	hooks    []Hook
}

// SetKey sets the "key" field.
func (skc *SigningKeyCreate) SetKey(s string) *SigningKeyCreate {
	skc.mutation.SetKey(s)
	return skc
}

// SetID sets the "id" field.
func (skc *SigningKeyCreate) SetID(s string) *SigningKeyCreate {
	skc.mutation.SetID(s)
	return skc
}

// SetKeySetID sets the "key_set" edge to the KeySet entity by ID.
func (skc *SigningKeyCreate) SetKeySetID(id string) *SigningKeyCreate {
	skc.mutation.SetKeySetID(id)
	return skc
}

// SetNillableKeySetID sets the "key_set" edge to the KeySet entity by ID if the given value is not nil.
func (skc *SigningKeyCreate) SetNillableKeySetID(id *string) *SigningKeyCreate {
	if id != nil {
		skc = skc.SetKeySetID(*id)
	}
	return skc
}

// SetKeySet sets the "key_set" edge to the KeySet entity.
func (skc *SigningKeyCreate) SetKeySet(k *KeySet) *SigningKeyCreate {
	return skc.SetKeySetID(k.ID)
}

// Mutation returns the SigningKeyMutation object of the builder.
func (skc *SigningKeyCreate) Mutation() *SigningKeyMutation {
	return skc.mutation
}

// Save creates the SigningKey in the database.
func (skc *SigningKeyCreate) Save(ctx context.Context) (*SigningKey, error) {
	return withHooks(ctx, skc.sqlSave, skc.mutation, skc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (skc *SigningKeyCreate) SaveX(ctx context.Context) *SigningKey {
	v, err := skc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (skc *SigningKeyCreate) Exec(ctx context.Context) error {
	_, err := skc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (skc *SigningKeyCreate) ExecX(ctx context.Context) {
	if err := skc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (skc *SigningKeyCreate) check() error {
	if _, ok := skc.mutation.Key(); !ok {
		return &ValidationError{Name: "key", err: errors.New(`ent: missing required field "SigningKey.key"`)}
	}
	if v, ok := skc.mutation.Key(); ok {
		if err := signingkey.KeyValidator(v); err != nil {
			return &ValidationError{Name: "key", err: fmt.Errorf(`ent: validator failed for field "SigningKey.key": %w`, err)}
		}
	}
	if v, ok := skc.mutation.ID(); ok {
		if err := signingkey.IDValidator(v); err != nil {
			return &ValidationError{Name: "id", err: fmt.Errorf(`ent: validator failed for field "SigningKey.id": %w`, err)}
		}
	}
	return nil
}

func (skc *SigningKeyCreate) sqlSave(ctx context.Context) (*SigningKey, error) {
	if err := skc.check(); err != nil {
		return nil, err
	}
	_node, _spec := skc.createSpec()
	if err := sqlgraph.CreateNode(ctx, skc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(string); ok {
			_node.ID = id
		} else {
			return nil, fmt.Errorf("unexpected SigningKey.ID type: %T", _spec.ID.Value)
		}
	}
	skc.mutation.id = &_node.ID
	skc.mutation.done = true
	return _node, nil
}

func (skc *SigningKeyCreate) createSpec() (*SigningKey, *sqlgraph.CreateSpec) {
	var (
		_node = &SigningKey{config: skc.config}
		_spec = sqlgraph.NewCreateSpec(signingkey.Table, sqlgraph.NewFieldSpec(signingkey.FieldID, field.TypeString))
	)
	if id, ok := skc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if value, ok := skc.mutation.Key(); ok {
		_spec.SetField(signingkey.FieldKey, field.TypeString, value)
		_node.Key = value
	}
	if nodes := skc.mutation.KeySetIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   signingkey.KeySetTable,
			Columns: []string{signingkey.KeySetColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(keyset.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.key_set_signing_keys = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// SigningKeyCreateBulk is the builder for creating many SigningKey entities in bulk.
type SigningKeyCreateBulk struct {
	config
	err      error
	builders []*SigningKeyCreate
}

// Save creates the SigningKey entities in the database.
func (skcb *SigningKeyCreateBulk) Save(ctx context.Context) ([]*SigningKey, error) {
	if skcb.err != nil {
		return nil, skcb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(skcb.builders))
	nodes := make([]*SigningKey, len(skcb.builders))
	mutators := make([]Mutator, len(skcb.builders))
	for i := range skcb.builders {
		func(i int, root context.Context) {
			builder := skcb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*SigningKeyMutation)
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
					_, err = mutators[i+1].Mutate(root, skcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, skcb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, skcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (skcb *SigningKeyCreateBulk) SaveX(ctx context.Context) []*SigningKey {
	v, err := skcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (skcb *SigningKeyCreateBulk) Exec(ctx context.Context) error {
	_, err := skcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (skcb *SigningKeyCreateBulk) ExecX(ctx context.Context) {
	if err := skcb.Exec(ctx); err != nil {
		panic(err)
	}
}