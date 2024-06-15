// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/keyset"
	"go.authbricks.com/bricks/ent/predicate"
	"go.authbricks.com/bricks/ent/signingkey"
)

// SigningKeyUpdate is the builder for updating SigningKey entities.
type SigningKeyUpdate struct {
	config
	hooks    []Hook
	mutation *SigningKeyMutation
}

// Where appends a list predicates to the SigningKeyUpdate builder.
func (sku *SigningKeyUpdate) Where(ps ...predicate.SigningKey) *SigningKeyUpdate {
	sku.mutation.Where(ps...)
	return sku
}

// SetKey sets the "key" field.
func (sku *SigningKeyUpdate) SetKey(s string) *SigningKeyUpdate {
	sku.mutation.SetKey(s)
	return sku
}

// SetNillableKey sets the "key" field if the given value is not nil.
func (sku *SigningKeyUpdate) SetNillableKey(s *string) *SigningKeyUpdate {
	if s != nil {
		sku.SetKey(*s)
	}
	return sku
}

// SetKeySetID sets the "key_set" edge to the KeySet entity by ID.
func (sku *SigningKeyUpdate) SetKeySetID(id string) *SigningKeyUpdate {
	sku.mutation.SetKeySetID(id)
	return sku
}

// SetNillableKeySetID sets the "key_set" edge to the KeySet entity by ID if the given value is not nil.
func (sku *SigningKeyUpdate) SetNillableKeySetID(id *string) *SigningKeyUpdate {
	if id != nil {
		sku = sku.SetKeySetID(*id)
	}
	return sku
}

// SetKeySet sets the "key_set" edge to the KeySet entity.
func (sku *SigningKeyUpdate) SetKeySet(k *KeySet) *SigningKeyUpdate {
	return sku.SetKeySetID(k.ID)
}

// Mutation returns the SigningKeyMutation object of the builder.
func (sku *SigningKeyUpdate) Mutation() *SigningKeyMutation {
	return sku.mutation
}

// ClearKeySet clears the "key_set" edge to the KeySet entity.
func (sku *SigningKeyUpdate) ClearKeySet() *SigningKeyUpdate {
	sku.mutation.ClearKeySet()
	return sku
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (sku *SigningKeyUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, sku.sqlSave, sku.mutation, sku.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (sku *SigningKeyUpdate) SaveX(ctx context.Context) int {
	affected, err := sku.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (sku *SigningKeyUpdate) Exec(ctx context.Context) error {
	_, err := sku.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (sku *SigningKeyUpdate) ExecX(ctx context.Context) {
	if err := sku.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (sku *SigningKeyUpdate) check() error {
	if v, ok := sku.mutation.Key(); ok {
		if err := signingkey.KeyValidator(v); err != nil {
			return &ValidationError{Name: "key", err: fmt.Errorf(`ent: validator failed for field "SigningKey.key": %w`, err)}
		}
	}
	return nil
}

func (sku *SigningKeyUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := sku.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(signingkey.Table, signingkey.Columns, sqlgraph.NewFieldSpec(signingkey.FieldID, field.TypeString))
	if ps := sku.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := sku.mutation.Key(); ok {
		_spec.SetField(signingkey.FieldKey, field.TypeString, value)
	}
	if sku.mutation.KeySetCleared() {
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
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := sku.mutation.KeySetIDs(); len(nodes) > 0 {
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
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, sku.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{signingkey.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	sku.mutation.done = true
	return n, nil
}

// SigningKeyUpdateOne is the builder for updating a single SigningKey entity.
type SigningKeyUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *SigningKeyMutation
}

// SetKey sets the "key" field.
func (skuo *SigningKeyUpdateOne) SetKey(s string) *SigningKeyUpdateOne {
	skuo.mutation.SetKey(s)
	return skuo
}

// SetNillableKey sets the "key" field if the given value is not nil.
func (skuo *SigningKeyUpdateOne) SetNillableKey(s *string) *SigningKeyUpdateOne {
	if s != nil {
		skuo.SetKey(*s)
	}
	return skuo
}

// SetKeySetID sets the "key_set" edge to the KeySet entity by ID.
func (skuo *SigningKeyUpdateOne) SetKeySetID(id string) *SigningKeyUpdateOne {
	skuo.mutation.SetKeySetID(id)
	return skuo
}

// SetNillableKeySetID sets the "key_set" edge to the KeySet entity by ID if the given value is not nil.
func (skuo *SigningKeyUpdateOne) SetNillableKeySetID(id *string) *SigningKeyUpdateOne {
	if id != nil {
		skuo = skuo.SetKeySetID(*id)
	}
	return skuo
}

// SetKeySet sets the "key_set" edge to the KeySet entity.
func (skuo *SigningKeyUpdateOne) SetKeySet(k *KeySet) *SigningKeyUpdateOne {
	return skuo.SetKeySetID(k.ID)
}

// Mutation returns the SigningKeyMutation object of the builder.
func (skuo *SigningKeyUpdateOne) Mutation() *SigningKeyMutation {
	return skuo.mutation
}

// ClearKeySet clears the "key_set" edge to the KeySet entity.
func (skuo *SigningKeyUpdateOne) ClearKeySet() *SigningKeyUpdateOne {
	skuo.mutation.ClearKeySet()
	return skuo
}

// Where appends a list predicates to the SigningKeyUpdate builder.
func (skuo *SigningKeyUpdateOne) Where(ps ...predicate.SigningKey) *SigningKeyUpdateOne {
	skuo.mutation.Where(ps...)
	return skuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (skuo *SigningKeyUpdateOne) Select(field string, fields ...string) *SigningKeyUpdateOne {
	skuo.fields = append([]string{field}, fields...)
	return skuo
}

// Save executes the query and returns the updated SigningKey entity.
func (skuo *SigningKeyUpdateOne) Save(ctx context.Context) (*SigningKey, error) {
	return withHooks(ctx, skuo.sqlSave, skuo.mutation, skuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (skuo *SigningKeyUpdateOne) SaveX(ctx context.Context) *SigningKey {
	node, err := skuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (skuo *SigningKeyUpdateOne) Exec(ctx context.Context) error {
	_, err := skuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (skuo *SigningKeyUpdateOne) ExecX(ctx context.Context) {
	if err := skuo.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (skuo *SigningKeyUpdateOne) check() error {
	if v, ok := skuo.mutation.Key(); ok {
		if err := signingkey.KeyValidator(v); err != nil {
			return &ValidationError{Name: "key", err: fmt.Errorf(`ent: validator failed for field "SigningKey.key": %w`, err)}
		}
	}
	return nil
}

func (skuo *SigningKeyUpdateOne) sqlSave(ctx context.Context) (_node *SigningKey, err error) {
	if err := skuo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(signingkey.Table, signingkey.Columns, sqlgraph.NewFieldSpec(signingkey.FieldID, field.TypeString))
	id, ok := skuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "SigningKey.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := skuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, signingkey.FieldID)
		for _, f := range fields {
			if !signingkey.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != signingkey.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := skuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := skuo.mutation.Key(); ok {
		_spec.SetField(signingkey.FieldKey, field.TypeString, value)
	}
	if skuo.mutation.KeySetCleared() {
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
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := skuo.mutation.KeySetIDs(); len(nodes) > 0 {
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
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &SigningKey{config: skuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, skuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{signingkey.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	skuo.mutation.done = true
	return _node, nil
}