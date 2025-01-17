// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/predicate"
	"go.authbricks.com/bricks/ent/tokenendpointconfig"
)

// TokenEndpointConfigDelete is the builder for deleting a TokenEndpointConfig entity.
type TokenEndpointConfigDelete struct {
	config
	hooks    []Hook
	mutation *TokenEndpointConfigMutation
}

// Where appends a list predicates to the TokenEndpointConfigDelete builder.
func (tecd *TokenEndpointConfigDelete) Where(ps ...predicate.TokenEndpointConfig) *TokenEndpointConfigDelete {
	tecd.mutation.Where(ps...)
	return tecd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (tecd *TokenEndpointConfigDelete) Exec(ctx context.Context) (int, error) {
	return withHooks(ctx, tecd.sqlExec, tecd.mutation, tecd.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (tecd *TokenEndpointConfigDelete) ExecX(ctx context.Context) int {
	n, err := tecd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (tecd *TokenEndpointConfigDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := sqlgraph.NewDeleteSpec(tokenendpointconfig.Table, sqlgraph.NewFieldSpec(tokenendpointconfig.FieldID, field.TypeString))
	if ps := tecd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, tecd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	tecd.mutation.done = true
	return affected, err
}

// TokenEndpointConfigDeleteOne is the builder for deleting a single TokenEndpointConfig entity.
type TokenEndpointConfigDeleteOne struct {
	tecd *TokenEndpointConfigDelete
}

// Where appends a list predicates to the TokenEndpointConfigDelete builder.
func (tecdo *TokenEndpointConfigDeleteOne) Where(ps ...predicate.TokenEndpointConfig) *TokenEndpointConfigDeleteOne {
	tecdo.tecd.mutation.Where(ps...)
	return tecdo
}

// Exec executes the deletion query.
func (tecdo *TokenEndpointConfigDeleteOne) Exec(ctx context.Context) error {
	n, err := tecdo.tecd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{tokenendpointconfig.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (tecdo *TokenEndpointConfigDeleteOne) ExecX(ctx context.Context) {
	if err := tecdo.Exec(ctx); err != nil {
		panic(err)
	}
}
