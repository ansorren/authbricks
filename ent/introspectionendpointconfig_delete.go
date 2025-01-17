// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/introspectionendpointconfig"
	"go.authbricks.com/bricks/ent/predicate"
)

// IntrospectionEndpointConfigDelete is the builder for deleting a IntrospectionEndpointConfig entity.
type IntrospectionEndpointConfigDelete struct {
	config
	hooks    []Hook
	mutation *IntrospectionEndpointConfigMutation
}

// Where appends a list predicates to the IntrospectionEndpointConfigDelete builder.
func (iecd *IntrospectionEndpointConfigDelete) Where(ps ...predicate.IntrospectionEndpointConfig) *IntrospectionEndpointConfigDelete {
	iecd.mutation.Where(ps...)
	return iecd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (iecd *IntrospectionEndpointConfigDelete) Exec(ctx context.Context) (int, error) {
	return withHooks(ctx, iecd.sqlExec, iecd.mutation, iecd.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (iecd *IntrospectionEndpointConfigDelete) ExecX(ctx context.Context) int {
	n, err := iecd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (iecd *IntrospectionEndpointConfigDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := sqlgraph.NewDeleteSpec(introspectionendpointconfig.Table, sqlgraph.NewFieldSpec(introspectionendpointconfig.FieldID, field.TypeString))
	if ps := iecd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, iecd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	iecd.mutation.done = true
	return affected, err
}

// IntrospectionEndpointConfigDeleteOne is the builder for deleting a single IntrospectionEndpointConfig entity.
type IntrospectionEndpointConfigDeleteOne struct {
	iecd *IntrospectionEndpointConfigDelete
}

// Where appends a list predicates to the IntrospectionEndpointConfigDelete builder.
func (iecdo *IntrospectionEndpointConfigDeleteOne) Where(ps ...predicate.IntrospectionEndpointConfig) *IntrospectionEndpointConfigDeleteOne {
	iecdo.iecd.mutation.Where(ps...)
	return iecdo
}

// Exec executes the deletion query.
func (iecdo *IntrospectionEndpointConfigDeleteOne) Exec(ctx context.Context) error {
	n, err := iecdo.iecd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{introspectionendpointconfig.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (iecdo *IntrospectionEndpointConfigDeleteOne) ExecX(ctx context.Context) {
	if err := iecdo.Exec(ctx); err != nil {
		panic(err)
	}
}
