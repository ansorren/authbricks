// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/predicate"
	"go.authbricks.com/bricks/ent/standardclaims"
)

// StandardClaimsDelete is the builder for deleting a StandardClaims entity.
type StandardClaimsDelete struct {
	config
	hooks    []Hook
	mutation *StandardClaimsMutation
}

// Where appends a list predicates to the StandardClaimsDelete builder.
func (scd *StandardClaimsDelete) Where(ps ...predicate.StandardClaims) *StandardClaimsDelete {
	scd.mutation.Where(ps...)
	return scd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (scd *StandardClaimsDelete) Exec(ctx context.Context) (int, error) {
	return withHooks(ctx, scd.sqlExec, scd.mutation, scd.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (scd *StandardClaimsDelete) ExecX(ctx context.Context) int {
	n, err := scd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (scd *StandardClaimsDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := sqlgraph.NewDeleteSpec(standardclaims.Table, sqlgraph.NewFieldSpec(standardclaims.FieldID, field.TypeInt))
	if ps := scd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, scd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	scd.mutation.done = true
	return affected, err
}

// StandardClaimsDeleteOne is the builder for deleting a single StandardClaims entity.
type StandardClaimsDeleteOne struct {
	scd *StandardClaimsDelete
}

// Where appends a list predicates to the StandardClaimsDelete builder.
func (scdo *StandardClaimsDeleteOne) Where(ps ...predicate.StandardClaims) *StandardClaimsDeleteOne {
	scdo.scd.mutation.Where(ps...)
	return scdo
}

// Exec executes the deletion query.
func (scdo *StandardClaimsDeleteOne) Exec(ctx context.Context) error {
	n, err := scdo.scd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{standardclaims.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (scdo *StandardClaimsDeleteOne) ExecX(ctx context.Context) {
	if err := scdo.Exec(ctx); err != nil {
		panic(err)
	}
}