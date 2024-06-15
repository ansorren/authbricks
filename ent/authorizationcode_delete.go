// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/authorizationcode"
	"go.authbricks.com/bricks/ent/predicate"
)

// AuthorizationCodeDelete is the builder for deleting a AuthorizationCode entity.
type AuthorizationCodeDelete struct {
	config
	hooks    []Hook
	mutation *AuthorizationCodeMutation
}

// Where appends a list predicates to the AuthorizationCodeDelete builder.
func (acd *AuthorizationCodeDelete) Where(ps ...predicate.AuthorizationCode) *AuthorizationCodeDelete {
	acd.mutation.Where(ps...)
	return acd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (acd *AuthorizationCodeDelete) Exec(ctx context.Context) (int, error) {
	return withHooks(ctx, acd.sqlExec, acd.mutation, acd.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (acd *AuthorizationCodeDelete) ExecX(ctx context.Context) int {
	n, err := acd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (acd *AuthorizationCodeDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := sqlgraph.NewDeleteSpec(authorizationcode.Table, sqlgraph.NewFieldSpec(authorizationcode.FieldID, field.TypeString))
	if ps := acd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, acd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	acd.mutation.done = true
	return affected, err
}

// AuthorizationCodeDeleteOne is the builder for deleting a single AuthorizationCode entity.
type AuthorizationCodeDeleteOne struct {
	acd *AuthorizationCodeDelete
}

// Where appends a list predicates to the AuthorizationCodeDelete builder.
func (acdo *AuthorizationCodeDeleteOne) Where(ps ...predicate.AuthorizationCode) *AuthorizationCodeDeleteOne {
	acdo.acd.mutation.Where(ps...)
	return acdo
}

// Exec executes the deletion query.
func (acdo *AuthorizationCodeDeleteOne) Exec(ctx context.Context) error {
	n, err := acdo.acd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{authorizationcode.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (acdo *AuthorizationCodeDeleteOne) ExecX(ctx context.Context) {
	if err := acdo.Exec(ctx); err != nil {
		panic(err)
	}
}
