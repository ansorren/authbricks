// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/loginendpointconfig"
	"go.authbricks.com/bricks/ent/predicate"
)

// LoginEndpointConfigDelete is the builder for deleting a LoginEndpointConfig entity.
type LoginEndpointConfigDelete struct {
	config
	hooks    []Hook
	mutation *LoginEndpointConfigMutation
}

// Where appends a list predicates to the LoginEndpointConfigDelete builder.
func (lecd *LoginEndpointConfigDelete) Where(ps ...predicate.LoginEndpointConfig) *LoginEndpointConfigDelete {
	lecd.mutation.Where(ps...)
	return lecd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (lecd *LoginEndpointConfigDelete) Exec(ctx context.Context) (int, error) {
	return withHooks(ctx, lecd.sqlExec, lecd.mutation, lecd.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (lecd *LoginEndpointConfigDelete) ExecX(ctx context.Context) int {
	n, err := lecd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (lecd *LoginEndpointConfigDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := sqlgraph.NewDeleteSpec(loginendpointconfig.Table, sqlgraph.NewFieldSpec(loginendpointconfig.FieldID, field.TypeString))
	if ps := lecd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, lecd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	lecd.mutation.done = true
	return affected, err
}

// LoginEndpointConfigDeleteOne is the builder for deleting a single LoginEndpointConfig entity.
type LoginEndpointConfigDeleteOne struct {
	lecd *LoginEndpointConfigDelete
}

// Where appends a list predicates to the LoginEndpointConfigDelete builder.
func (lecdo *LoginEndpointConfigDeleteOne) Where(ps ...predicate.LoginEndpointConfig) *LoginEndpointConfigDeleteOne {
	lecdo.lecd.mutation.Where(ps...)
	return lecdo
}

// Exec executes the deletion query.
func (lecdo *LoginEndpointConfigDeleteOne) Exec(ctx context.Context) error {
	n, err := lecdo.lecd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{loginendpointconfig.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (lecdo *LoginEndpointConfigDeleteOne) ExecX(ctx context.Context) {
	if err := lecdo.Exec(ctx); err != nil {
		panic(err)
	}
}
