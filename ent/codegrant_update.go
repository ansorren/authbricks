// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/dialect/sql/sqljson"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/application"
	"go.authbricks.com/bricks/ent/codegrant"
	"go.authbricks.com/bricks/ent/predicate"
)

// CodeGrantUpdate is the builder for updating CodeGrant entities.
type CodeGrantUpdate struct {
	config
	hooks    []Hook
	mutation *CodeGrantMutation
}

// Where appends a list predicates to the CodeGrantUpdate builder.
func (cgu *CodeGrantUpdate) Where(ps ...predicate.CodeGrant) *CodeGrantUpdate {
	cgu.mutation.Where(ps...)
	return cgu
}

// SetScopes sets the "scopes" field.
func (cgu *CodeGrantUpdate) SetScopes(s []string) *CodeGrantUpdate {
	cgu.mutation.SetScopes(s)
	return cgu
}

// AppendScopes appends s to the "scopes" field.
func (cgu *CodeGrantUpdate) AppendScopes(s []string) *CodeGrantUpdate {
	cgu.mutation.AppendScopes(s)
	return cgu
}

// SetCallbacks sets the "callbacks" field.
func (cgu *CodeGrantUpdate) SetCallbacks(s []string) *CodeGrantUpdate {
	cgu.mutation.SetCallbacks(s)
	return cgu
}

// AppendCallbacks appends s to the "callbacks" field.
func (cgu *CodeGrantUpdate) AppendCallbacks(s []string) *CodeGrantUpdate {
	cgu.mutation.AppendCallbacks(s)
	return cgu
}

// SetApplicationID sets the "application" edge to the Application entity by ID.
func (cgu *CodeGrantUpdate) SetApplicationID(id string) *CodeGrantUpdate {
	cgu.mutation.SetApplicationID(id)
	return cgu
}

// SetNillableApplicationID sets the "application" edge to the Application entity by ID if the given value is not nil.
func (cgu *CodeGrantUpdate) SetNillableApplicationID(id *string) *CodeGrantUpdate {
	if id != nil {
		cgu = cgu.SetApplicationID(*id)
	}
	return cgu
}

// SetApplication sets the "application" edge to the Application entity.
func (cgu *CodeGrantUpdate) SetApplication(a *Application) *CodeGrantUpdate {
	return cgu.SetApplicationID(a.ID)
}

// Mutation returns the CodeGrantMutation object of the builder.
func (cgu *CodeGrantUpdate) Mutation() *CodeGrantMutation {
	return cgu.mutation
}

// ClearApplication clears the "application" edge to the Application entity.
func (cgu *CodeGrantUpdate) ClearApplication() *CodeGrantUpdate {
	cgu.mutation.ClearApplication()
	return cgu
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (cgu *CodeGrantUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, cgu.sqlSave, cgu.mutation, cgu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (cgu *CodeGrantUpdate) SaveX(ctx context.Context) int {
	affected, err := cgu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (cgu *CodeGrantUpdate) Exec(ctx context.Context) error {
	_, err := cgu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (cgu *CodeGrantUpdate) ExecX(ctx context.Context) {
	if err := cgu.Exec(ctx); err != nil {
		panic(err)
	}
}

func (cgu *CodeGrantUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(codegrant.Table, codegrant.Columns, sqlgraph.NewFieldSpec(codegrant.FieldID, field.TypeString))
	if ps := cgu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := cgu.mutation.Scopes(); ok {
		_spec.SetField(codegrant.FieldScopes, field.TypeJSON, value)
	}
	if value, ok := cgu.mutation.AppendedScopes(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, codegrant.FieldScopes, value)
		})
	}
	if value, ok := cgu.mutation.Callbacks(); ok {
		_spec.SetField(codegrant.FieldCallbacks, field.TypeJSON, value)
	}
	if value, ok := cgu.mutation.AppendedCallbacks(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, codegrant.FieldCallbacks, value)
		})
	}
	if cgu.mutation.ApplicationCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   codegrant.ApplicationTable,
			Columns: []string{codegrant.ApplicationColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(application.FieldID, field.TypeString),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := cgu.mutation.ApplicationIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   codegrant.ApplicationTable,
			Columns: []string{codegrant.ApplicationColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(application.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, cgu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{codegrant.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	cgu.mutation.done = true
	return n, nil
}

// CodeGrantUpdateOne is the builder for updating a single CodeGrant entity.
type CodeGrantUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *CodeGrantMutation
}

// SetScopes sets the "scopes" field.
func (cguo *CodeGrantUpdateOne) SetScopes(s []string) *CodeGrantUpdateOne {
	cguo.mutation.SetScopes(s)
	return cguo
}

// AppendScopes appends s to the "scopes" field.
func (cguo *CodeGrantUpdateOne) AppendScopes(s []string) *CodeGrantUpdateOne {
	cguo.mutation.AppendScopes(s)
	return cguo
}

// SetCallbacks sets the "callbacks" field.
func (cguo *CodeGrantUpdateOne) SetCallbacks(s []string) *CodeGrantUpdateOne {
	cguo.mutation.SetCallbacks(s)
	return cguo
}

// AppendCallbacks appends s to the "callbacks" field.
func (cguo *CodeGrantUpdateOne) AppendCallbacks(s []string) *CodeGrantUpdateOne {
	cguo.mutation.AppendCallbacks(s)
	return cguo
}

// SetApplicationID sets the "application" edge to the Application entity by ID.
func (cguo *CodeGrantUpdateOne) SetApplicationID(id string) *CodeGrantUpdateOne {
	cguo.mutation.SetApplicationID(id)
	return cguo
}

// SetNillableApplicationID sets the "application" edge to the Application entity by ID if the given value is not nil.
func (cguo *CodeGrantUpdateOne) SetNillableApplicationID(id *string) *CodeGrantUpdateOne {
	if id != nil {
		cguo = cguo.SetApplicationID(*id)
	}
	return cguo
}

// SetApplication sets the "application" edge to the Application entity.
func (cguo *CodeGrantUpdateOne) SetApplication(a *Application) *CodeGrantUpdateOne {
	return cguo.SetApplicationID(a.ID)
}

// Mutation returns the CodeGrantMutation object of the builder.
func (cguo *CodeGrantUpdateOne) Mutation() *CodeGrantMutation {
	return cguo.mutation
}

// ClearApplication clears the "application" edge to the Application entity.
func (cguo *CodeGrantUpdateOne) ClearApplication() *CodeGrantUpdateOne {
	cguo.mutation.ClearApplication()
	return cguo
}

// Where appends a list predicates to the CodeGrantUpdate builder.
func (cguo *CodeGrantUpdateOne) Where(ps ...predicate.CodeGrant) *CodeGrantUpdateOne {
	cguo.mutation.Where(ps...)
	return cguo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (cguo *CodeGrantUpdateOne) Select(field string, fields ...string) *CodeGrantUpdateOne {
	cguo.fields = append([]string{field}, fields...)
	return cguo
}

// Save executes the query and returns the updated CodeGrant entity.
func (cguo *CodeGrantUpdateOne) Save(ctx context.Context) (*CodeGrant, error) {
	return withHooks(ctx, cguo.sqlSave, cguo.mutation, cguo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (cguo *CodeGrantUpdateOne) SaveX(ctx context.Context) *CodeGrant {
	node, err := cguo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (cguo *CodeGrantUpdateOne) Exec(ctx context.Context) error {
	_, err := cguo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (cguo *CodeGrantUpdateOne) ExecX(ctx context.Context) {
	if err := cguo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (cguo *CodeGrantUpdateOne) sqlSave(ctx context.Context) (_node *CodeGrant, err error) {
	_spec := sqlgraph.NewUpdateSpec(codegrant.Table, codegrant.Columns, sqlgraph.NewFieldSpec(codegrant.FieldID, field.TypeString))
	id, ok := cguo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "CodeGrant.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := cguo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, codegrant.FieldID)
		for _, f := range fields {
			if !codegrant.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != codegrant.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := cguo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := cguo.mutation.Scopes(); ok {
		_spec.SetField(codegrant.FieldScopes, field.TypeJSON, value)
	}
	if value, ok := cguo.mutation.AppendedScopes(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, codegrant.FieldScopes, value)
		})
	}
	if value, ok := cguo.mutation.Callbacks(); ok {
		_spec.SetField(codegrant.FieldCallbacks, field.TypeJSON, value)
	}
	if value, ok := cguo.mutation.AppendedCallbacks(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, codegrant.FieldCallbacks, value)
		})
	}
	if cguo.mutation.ApplicationCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   codegrant.ApplicationTable,
			Columns: []string{codegrant.ApplicationColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(application.FieldID, field.TypeString),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := cguo.mutation.ApplicationIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   codegrant.ApplicationTable,
			Columns: []string{codegrant.ApplicationColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(application.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &CodeGrant{config: cguo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, cguo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{codegrant.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	cguo.mutation.done = true
	return _node, nil
}
