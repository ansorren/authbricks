// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/authorizationpayload"
	"go.authbricks.com/bricks/ent/predicate"
	"go.authbricks.com/bricks/ent/session"
)

// SessionUpdate is the builder for updating Session entities.
type SessionUpdate struct {
	config
	hooks    []Hook
	mutation *SessionMutation
}

// Where appends a list predicates to the SessionUpdate builder.
func (su *SessionUpdate) Where(ps ...predicate.Session) *SessionUpdate {
	su.mutation.Where(ps...)
	return su
}

// SetCreatedAt sets the "created_at" field.
func (su *SessionUpdate) SetCreatedAt(i int64) *SessionUpdate {
	su.mutation.ResetCreatedAt()
	su.mutation.SetCreatedAt(i)
	return su
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (su *SessionUpdate) SetNillableCreatedAt(i *int64) *SessionUpdate {
	if i != nil {
		su.SetCreatedAt(*i)
	}
	return su
}

// AddCreatedAt adds i to the "created_at" field.
func (su *SessionUpdate) AddCreatedAt(i int64) *SessionUpdate {
	su.mutation.AddCreatedAt(i)
	return su
}

// SetServiceName sets the "service_name" field.
func (su *SessionUpdate) SetServiceName(s string) *SessionUpdate {
	su.mutation.SetServiceName(s)
	return su
}

// SetNillableServiceName sets the "service_name" field if the given value is not nil.
func (su *SessionUpdate) SetNillableServiceName(s *string) *SessionUpdate {
	if s != nil {
		su.SetServiceName(*s)
	}
	return su
}

// SetAuthorizationPayloadID sets the "authorization_payload" edge to the AuthorizationPayload entity by ID.
func (su *SessionUpdate) SetAuthorizationPayloadID(id string) *SessionUpdate {
	su.mutation.SetAuthorizationPayloadID(id)
	return su
}

// SetNillableAuthorizationPayloadID sets the "authorization_payload" edge to the AuthorizationPayload entity by ID if the given value is not nil.
func (su *SessionUpdate) SetNillableAuthorizationPayloadID(id *string) *SessionUpdate {
	if id != nil {
		su = su.SetAuthorizationPayloadID(*id)
	}
	return su
}

// SetAuthorizationPayload sets the "authorization_payload" edge to the AuthorizationPayload entity.
func (su *SessionUpdate) SetAuthorizationPayload(a *AuthorizationPayload) *SessionUpdate {
	return su.SetAuthorizationPayloadID(a.ID)
}

// Mutation returns the SessionMutation object of the builder.
func (su *SessionUpdate) Mutation() *SessionMutation {
	return su.mutation
}

// ClearAuthorizationPayload clears the "authorization_payload" edge to the AuthorizationPayload entity.
func (su *SessionUpdate) ClearAuthorizationPayload() *SessionUpdate {
	su.mutation.ClearAuthorizationPayload()
	return su
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (su *SessionUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, su.sqlSave, su.mutation, su.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (su *SessionUpdate) SaveX(ctx context.Context) int {
	affected, err := su.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (su *SessionUpdate) Exec(ctx context.Context) error {
	_, err := su.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (su *SessionUpdate) ExecX(ctx context.Context) {
	if err := su.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (su *SessionUpdate) check() error {
	if v, ok := su.mutation.CreatedAt(); ok {
		if err := session.CreatedAtValidator(v); err != nil {
			return &ValidationError{Name: "created_at", err: fmt.Errorf(`ent: validator failed for field "Session.created_at": %w`, err)}
		}
	}
	if v, ok := su.mutation.ServiceName(); ok {
		if err := session.ServiceNameValidator(v); err != nil {
			return &ValidationError{Name: "service_name", err: fmt.Errorf(`ent: validator failed for field "Session.service_name": %w`, err)}
		}
	}
	return nil
}

func (su *SessionUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := su.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(session.Table, session.Columns, sqlgraph.NewFieldSpec(session.FieldID, field.TypeString))
	if ps := su.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := su.mutation.CreatedAt(); ok {
		_spec.SetField(session.FieldCreatedAt, field.TypeInt64, value)
	}
	if value, ok := su.mutation.AddedCreatedAt(); ok {
		_spec.AddField(session.FieldCreatedAt, field.TypeInt64, value)
	}
	if value, ok := su.mutation.ServiceName(); ok {
		_spec.SetField(session.FieldServiceName, field.TypeString, value)
	}
	if su.mutation.AuthorizationPayloadCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   session.AuthorizationPayloadTable,
			Columns: []string{session.AuthorizationPayloadColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(authorizationpayload.FieldID, field.TypeString),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := su.mutation.AuthorizationPayloadIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   session.AuthorizationPayloadTable,
			Columns: []string{session.AuthorizationPayloadColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(authorizationpayload.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, su.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{session.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	su.mutation.done = true
	return n, nil
}

// SessionUpdateOne is the builder for updating a single Session entity.
type SessionUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *SessionMutation
}

// SetCreatedAt sets the "created_at" field.
func (suo *SessionUpdateOne) SetCreatedAt(i int64) *SessionUpdateOne {
	suo.mutation.ResetCreatedAt()
	suo.mutation.SetCreatedAt(i)
	return suo
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (suo *SessionUpdateOne) SetNillableCreatedAt(i *int64) *SessionUpdateOne {
	if i != nil {
		suo.SetCreatedAt(*i)
	}
	return suo
}

// AddCreatedAt adds i to the "created_at" field.
func (suo *SessionUpdateOne) AddCreatedAt(i int64) *SessionUpdateOne {
	suo.mutation.AddCreatedAt(i)
	return suo
}

// SetServiceName sets the "service_name" field.
func (suo *SessionUpdateOne) SetServiceName(s string) *SessionUpdateOne {
	suo.mutation.SetServiceName(s)
	return suo
}

// SetNillableServiceName sets the "service_name" field if the given value is not nil.
func (suo *SessionUpdateOne) SetNillableServiceName(s *string) *SessionUpdateOne {
	if s != nil {
		suo.SetServiceName(*s)
	}
	return suo
}

// SetAuthorizationPayloadID sets the "authorization_payload" edge to the AuthorizationPayload entity by ID.
func (suo *SessionUpdateOne) SetAuthorizationPayloadID(id string) *SessionUpdateOne {
	suo.mutation.SetAuthorizationPayloadID(id)
	return suo
}

// SetNillableAuthorizationPayloadID sets the "authorization_payload" edge to the AuthorizationPayload entity by ID if the given value is not nil.
func (suo *SessionUpdateOne) SetNillableAuthorizationPayloadID(id *string) *SessionUpdateOne {
	if id != nil {
		suo = suo.SetAuthorizationPayloadID(*id)
	}
	return suo
}

// SetAuthorizationPayload sets the "authorization_payload" edge to the AuthorizationPayload entity.
func (suo *SessionUpdateOne) SetAuthorizationPayload(a *AuthorizationPayload) *SessionUpdateOne {
	return suo.SetAuthorizationPayloadID(a.ID)
}

// Mutation returns the SessionMutation object of the builder.
func (suo *SessionUpdateOne) Mutation() *SessionMutation {
	return suo.mutation
}

// ClearAuthorizationPayload clears the "authorization_payload" edge to the AuthorizationPayload entity.
func (suo *SessionUpdateOne) ClearAuthorizationPayload() *SessionUpdateOne {
	suo.mutation.ClearAuthorizationPayload()
	return suo
}

// Where appends a list predicates to the SessionUpdate builder.
func (suo *SessionUpdateOne) Where(ps ...predicate.Session) *SessionUpdateOne {
	suo.mutation.Where(ps...)
	return suo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (suo *SessionUpdateOne) Select(field string, fields ...string) *SessionUpdateOne {
	suo.fields = append([]string{field}, fields...)
	return suo
}

// Save executes the query and returns the updated Session entity.
func (suo *SessionUpdateOne) Save(ctx context.Context) (*Session, error) {
	return withHooks(ctx, suo.sqlSave, suo.mutation, suo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (suo *SessionUpdateOne) SaveX(ctx context.Context) *Session {
	node, err := suo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (suo *SessionUpdateOne) Exec(ctx context.Context) error {
	_, err := suo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (suo *SessionUpdateOne) ExecX(ctx context.Context) {
	if err := suo.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (suo *SessionUpdateOne) check() error {
	if v, ok := suo.mutation.CreatedAt(); ok {
		if err := session.CreatedAtValidator(v); err != nil {
			return &ValidationError{Name: "created_at", err: fmt.Errorf(`ent: validator failed for field "Session.created_at": %w`, err)}
		}
	}
	if v, ok := suo.mutation.ServiceName(); ok {
		if err := session.ServiceNameValidator(v); err != nil {
			return &ValidationError{Name: "service_name", err: fmt.Errorf(`ent: validator failed for field "Session.service_name": %w`, err)}
		}
	}
	return nil
}

func (suo *SessionUpdateOne) sqlSave(ctx context.Context) (_node *Session, err error) {
	if err := suo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(session.Table, session.Columns, sqlgraph.NewFieldSpec(session.FieldID, field.TypeString))
	id, ok := suo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "Session.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := suo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, session.FieldID)
		for _, f := range fields {
			if !session.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != session.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := suo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := suo.mutation.CreatedAt(); ok {
		_spec.SetField(session.FieldCreatedAt, field.TypeInt64, value)
	}
	if value, ok := suo.mutation.AddedCreatedAt(); ok {
		_spec.AddField(session.FieldCreatedAt, field.TypeInt64, value)
	}
	if value, ok := suo.mutation.ServiceName(); ok {
		_spec.SetField(session.FieldServiceName, field.TypeString, value)
	}
	if suo.mutation.AuthorizationPayloadCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   session.AuthorizationPayloadTable,
			Columns: []string{session.AuthorizationPayloadColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(authorizationpayload.FieldID, field.TypeString),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := suo.mutation.AuthorizationPayloadIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   session.AuthorizationPayloadTable,
			Columns: []string{session.AuthorizationPayloadColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(authorizationpayload.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &Session{config: suo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, suo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{session.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	suo.mutation.done = true
	return _node, nil
}
