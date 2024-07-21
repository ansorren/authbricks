// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/predicate"
	"go.authbricks.com/bricks/ent/wellknownendpointconfig"
)

// WellKnownEndpointConfigDelete is the builder for deleting a WellKnownEndpointConfig entity.
type WellKnownEndpointConfigDelete struct {
	config
	hooks    []Hook
	mutation *WellKnownEndpointConfigMutation
}

// Where appends a list predicates to the WellKnownEndpointConfigDelete builder.
func (wkecd *WellKnownEndpointConfigDelete) Where(ps ...predicate.WellKnownEndpointConfig) *WellKnownEndpointConfigDelete {
	wkecd.mutation.Where(ps...)
	return wkecd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (wkecd *WellKnownEndpointConfigDelete) Exec(ctx context.Context) (int, error) {
	return withHooks(ctx, wkecd.sqlExec, wkecd.mutation, wkecd.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (wkecd *WellKnownEndpointConfigDelete) ExecX(ctx context.Context) int {
	n, err := wkecd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (wkecd *WellKnownEndpointConfigDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := sqlgraph.NewDeleteSpec(wellknownendpointconfig.Table, sqlgraph.NewFieldSpec(wellknownendpointconfig.FieldID, field.TypeString))
	if ps := wkecd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, wkecd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	wkecd.mutation.done = true
	return affected, err
}

// WellKnownEndpointConfigDeleteOne is the builder for deleting a single WellKnownEndpointConfig entity.
type WellKnownEndpointConfigDeleteOne struct {
	wkecd *WellKnownEndpointConfigDelete
}

// Where appends a list predicates to the WellKnownEndpointConfigDelete builder.
func (wkecdo *WellKnownEndpointConfigDeleteOne) Where(ps ...predicate.WellKnownEndpointConfig) *WellKnownEndpointConfigDeleteOne {
	wkecdo.wkecd.mutation.Where(ps...)
	return wkecdo
}

// Exec executes the deletion query.
func (wkecdo *WellKnownEndpointConfigDeleteOne) Exec(ctx context.Context) error {
	n, err := wkecdo.wkecd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{wellknownendpointconfig.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (wkecdo *WellKnownEndpointConfigDeleteOne) ExecX(ctx context.Context) {
	if err := wkecdo.Exec(ctx); err != nil {
		panic(err)
	}
}
