// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/jwksendpointconfig"
	"go.authbricks.com/bricks/ent/predicate"
)

// JwksEndpointConfigDelete is the builder for deleting a JwksEndpointConfig entity.
type JwksEndpointConfigDelete struct {
	config
	hooks    []Hook
	mutation *JwksEndpointConfigMutation
}

// Where appends a list predicates to the JwksEndpointConfigDelete builder.
func (jecd *JwksEndpointConfigDelete) Where(ps ...predicate.JwksEndpointConfig) *JwksEndpointConfigDelete {
	jecd.mutation.Where(ps...)
	return jecd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (jecd *JwksEndpointConfigDelete) Exec(ctx context.Context) (int, error) {
	return withHooks(ctx, jecd.sqlExec, jecd.mutation, jecd.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (jecd *JwksEndpointConfigDelete) ExecX(ctx context.Context) int {
	n, err := jecd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (jecd *JwksEndpointConfigDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := sqlgraph.NewDeleteSpec(jwksendpointconfig.Table, sqlgraph.NewFieldSpec(jwksendpointconfig.FieldID, field.TypeString))
	if ps := jecd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, jecd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	jecd.mutation.done = true
	return affected, err
}

// JwksEndpointConfigDeleteOne is the builder for deleting a single JwksEndpointConfig entity.
type JwksEndpointConfigDeleteOne struct {
	jecd *JwksEndpointConfigDelete
}

// Where appends a list predicates to the JwksEndpointConfigDelete builder.
func (jecdo *JwksEndpointConfigDeleteOne) Where(ps ...predicate.JwksEndpointConfig) *JwksEndpointConfigDeleteOne {
	jecdo.jecd.mutation.Where(ps...)
	return jecdo
}

// Exec executes the deletion query.
func (jecdo *JwksEndpointConfigDeleteOne) Exec(ctx context.Context) error {
	n, err := jecdo.jecd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{jwksendpointconfig.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (jecdo *JwksEndpointConfigDeleteOne) ExecX(ctx context.Context) {
	if err := jecdo.Exec(ctx); err != nil {
		panic(err)
	}
}