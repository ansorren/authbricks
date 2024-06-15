// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/predicate"
	"go.authbricks.com/bricks/ent/refreshtoken"
)

// RefreshTokenDelete is the builder for deleting a RefreshToken entity.
type RefreshTokenDelete struct {
	config
	hooks    []Hook
	mutation *RefreshTokenMutation
}

// Where appends a list predicates to the RefreshTokenDelete builder.
func (rtd *RefreshTokenDelete) Where(ps ...predicate.RefreshToken) *RefreshTokenDelete {
	rtd.mutation.Where(ps...)
	return rtd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (rtd *RefreshTokenDelete) Exec(ctx context.Context) (int, error) {
	return withHooks(ctx, rtd.sqlExec, rtd.mutation, rtd.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (rtd *RefreshTokenDelete) ExecX(ctx context.Context) int {
	n, err := rtd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (rtd *RefreshTokenDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := sqlgraph.NewDeleteSpec(refreshtoken.Table, sqlgraph.NewFieldSpec(refreshtoken.FieldID, field.TypeString))
	if ps := rtd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, rtd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	rtd.mutation.done = true
	return affected, err
}

// RefreshTokenDeleteOne is the builder for deleting a single RefreshToken entity.
type RefreshTokenDeleteOne struct {
	rtd *RefreshTokenDelete
}

// Where appends a list predicates to the RefreshTokenDelete builder.
func (rtdo *RefreshTokenDeleteOne) Where(ps ...predicate.RefreshToken) *RefreshTokenDeleteOne {
	rtdo.rtd.mutation.Where(ps...)
	return rtdo
}

// Exec executes the deletion query.
func (rtdo *RefreshTokenDeleteOne) Exec(ctx context.Context) error {
	n, err := rtdo.rtd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{refreshtoken.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (rtdo *RefreshTokenDeleteOne) ExecX(ctx context.Context) {
	if err := rtdo.Exec(ctx); err != nil {
		panic(err)
	}
}
