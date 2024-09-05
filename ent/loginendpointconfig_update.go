// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/loginendpointconfig"
	"go.authbricks.com/bricks/ent/predicate"
	"go.authbricks.com/bricks/ent/service"
)

// LoginEndpointConfigUpdate is the builder for updating LoginEndpointConfig entities.
type LoginEndpointConfigUpdate struct {
	config
	hooks    []Hook
	mutation *LoginEndpointConfigMutation
}

// Where appends a list predicates to the LoginEndpointConfigUpdate builder.
func (lecu *LoginEndpointConfigUpdate) Where(ps ...predicate.LoginEndpointConfig) *LoginEndpointConfigUpdate {
	lecu.mutation.Where(ps...)
	return lecu
}

// SetEndpoint sets the "endpoint" field.
func (lecu *LoginEndpointConfigUpdate) SetEndpoint(s string) *LoginEndpointConfigUpdate {
	lecu.mutation.SetEndpoint(s)
	return lecu
}

// SetNillableEndpoint sets the "endpoint" field if the given value is not nil.
func (lecu *LoginEndpointConfigUpdate) SetNillableEndpoint(s *string) *LoginEndpointConfigUpdate {
	if s != nil {
		lecu.SetEndpoint(*s)
	}
	return lecu
}

// SetSessionTimeout sets the "session_timeout" field.
func (lecu *LoginEndpointConfigUpdate) SetSessionTimeout(i int64) *LoginEndpointConfigUpdate {
	lecu.mutation.ResetSessionTimeout()
	lecu.mutation.SetSessionTimeout(i)
	return lecu
}

// SetNillableSessionTimeout sets the "session_timeout" field if the given value is not nil.
func (lecu *LoginEndpointConfigUpdate) SetNillableSessionTimeout(i *int64) *LoginEndpointConfigUpdate {
	if i != nil {
		lecu.SetSessionTimeout(*i)
	}
	return lecu
}

// AddSessionTimeout adds i to the "session_timeout" field.
func (lecu *LoginEndpointConfigUpdate) AddSessionTimeout(i int64) *LoginEndpointConfigUpdate {
	lecu.mutation.AddSessionTimeout(i)
	return lecu
}

// SetServiceID sets the "service" edge to the Service entity by ID.
func (lecu *LoginEndpointConfigUpdate) SetServiceID(id string) *LoginEndpointConfigUpdate {
	lecu.mutation.SetServiceID(id)
	return lecu
}

// SetService sets the "service" edge to the Service entity.
func (lecu *LoginEndpointConfigUpdate) SetService(s *Service) *LoginEndpointConfigUpdate {
	return lecu.SetServiceID(s.ID)
}

// Mutation returns the LoginEndpointConfigMutation object of the builder.
func (lecu *LoginEndpointConfigUpdate) Mutation() *LoginEndpointConfigMutation {
	return lecu.mutation
}

// ClearService clears the "service" edge to the Service entity.
func (lecu *LoginEndpointConfigUpdate) ClearService() *LoginEndpointConfigUpdate {
	lecu.mutation.ClearService()
	return lecu
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (lecu *LoginEndpointConfigUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, lecu.sqlSave, lecu.mutation, lecu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (lecu *LoginEndpointConfigUpdate) SaveX(ctx context.Context) int {
	affected, err := lecu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (lecu *LoginEndpointConfigUpdate) Exec(ctx context.Context) error {
	_, err := lecu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (lecu *LoginEndpointConfigUpdate) ExecX(ctx context.Context) {
	if err := lecu.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (lecu *LoginEndpointConfigUpdate) check() error {
	if v, ok := lecu.mutation.Endpoint(); ok {
		if err := loginendpointconfig.EndpointValidator(v); err != nil {
			return &ValidationError{Name: "endpoint", err: fmt.Errorf(`ent: validator failed for field "LoginEndpointConfig.endpoint": %w`, err)}
		}
	}
	if v, ok := lecu.mutation.SessionTimeout(); ok {
		if err := loginendpointconfig.SessionTimeoutValidator(v); err != nil {
			return &ValidationError{Name: "session_timeout", err: fmt.Errorf(`ent: validator failed for field "LoginEndpointConfig.session_timeout": %w`, err)}
		}
	}
	if _, ok := lecu.mutation.ServiceID(); lecu.mutation.ServiceCleared() && !ok {
		return errors.New(`ent: clearing a required unique edge "LoginEndpointConfig.service"`)
	}
	return nil
}

func (lecu *LoginEndpointConfigUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := lecu.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(loginendpointconfig.Table, loginendpointconfig.Columns, sqlgraph.NewFieldSpec(loginendpointconfig.FieldID, field.TypeString))
	if ps := lecu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := lecu.mutation.Endpoint(); ok {
		_spec.SetField(loginendpointconfig.FieldEndpoint, field.TypeString, value)
	}
	if value, ok := lecu.mutation.SessionTimeout(); ok {
		_spec.SetField(loginendpointconfig.FieldSessionTimeout, field.TypeInt64, value)
	}
	if value, ok := lecu.mutation.AddedSessionTimeout(); ok {
		_spec.AddField(loginendpointconfig.FieldSessionTimeout, field.TypeInt64, value)
	}
	if lecu.mutation.ServiceCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   loginendpointconfig.ServiceTable,
			Columns: []string{loginendpointconfig.ServiceColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(service.FieldID, field.TypeString),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := lecu.mutation.ServiceIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   loginendpointconfig.ServiceTable,
			Columns: []string{loginendpointconfig.ServiceColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(service.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, lecu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{loginendpointconfig.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	lecu.mutation.done = true
	return n, nil
}

// LoginEndpointConfigUpdateOne is the builder for updating a single LoginEndpointConfig entity.
type LoginEndpointConfigUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *LoginEndpointConfigMutation
}

// SetEndpoint sets the "endpoint" field.
func (lecuo *LoginEndpointConfigUpdateOne) SetEndpoint(s string) *LoginEndpointConfigUpdateOne {
	lecuo.mutation.SetEndpoint(s)
	return lecuo
}

// SetNillableEndpoint sets the "endpoint" field if the given value is not nil.
func (lecuo *LoginEndpointConfigUpdateOne) SetNillableEndpoint(s *string) *LoginEndpointConfigUpdateOne {
	if s != nil {
		lecuo.SetEndpoint(*s)
	}
	return lecuo
}

// SetSessionTimeout sets the "session_timeout" field.
func (lecuo *LoginEndpointConfigUpdateOne) SetSessionTimeout(i int64) *LoginEndpointConfigUpdateOne {
	lecuo.mutation.ResetSessionTimeout()
	lecuo.mutation.SetSessionTimeout(i)
	return lecuo
}

// SetNillableSessionTimeout sets the "session_timeout" field if the given value is not nil.
func (lecuo *LoginEndpointConfigUpdateOne) SetNillableSessionTimeout(i *int64) *LoginEndpointConfigUpdateOne {
	if i != nil {
		lecuo.SetSessionTimeout(*i)
	}
	return lecuo
}

// AddSessionTimeout adds i to the "session_timeout" field.
func (lecuo *LoginEndpointConfigUpdateOne) AddSessionTimeout(i int64) *LoginEndpointConfigUpdateOne {
	lecuo.mutation.AddSessionTimeout(i)
	return lecuo
}

// SetServiceID sets the "service" edge to the Service entity by ID.
func (lecuo *LoginEndpointConfigUpdateOne) SetServiceID(id string) *LoginEndpointConfigUpdateOne {
	lecuo.mutation.SetServiceID(id)
	return lecuo
}

// SetService sets the "service" edge to the Service entity.
func (lecuo *LoginEndpointConfigUpdateOne) SetService(s *Service) *LoginEndpointConfigUpdateOne {
	return lecuo.SetServiceID(s.ID)
}

// Mutation returns the LoginEndpointConfigMutation object of the builder.
func (lecuo *LoginEndpointConfigUpdateOne) Mutation() *LoginEndpointConfigMutation {
	return lecuo.mutation
}

// ClearService clears the "service" edge to the Service entity.
func (lecuo *LoginEndpointConfigUpdateOne) ClearService() *LoginEndpointConfigUpdateOne {
	lecuo.mutation.ClearService()
	return lecuo
}

// Where appends a list predicates to the LoginEndpointConfigUpdate builder.
func (lecuo *LoginEndpointConfigUpdateOne) Where(ps ...predicate.LoginEndpointConfig) *LoginEndpointConfigUpdateOne {
	lecuo.mutation.Where(ps...)
	return lecuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (lecuo *LoginEndpointConfigUpdateOne) Select(field string, fields ...string) *LoginEndpointConfigUpdateOne {
	lecuo.fields = append([]string{field}, fields...)
	return lecuo
}

// Save executes the query and returns the updated LoginEndpointConfig entity.
func (lecuo *LoginEndpointConfigUpdateOne) Save(ctx context.Context) (*LoginEndpointConfig, error) {
	return withHooks(ctx, lecuo.sqlSave, lecuo.mutation, lecuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (lecuo *LoginEndpointConfigUpdateOne) SaveX(ctx context.Context) *LoginEndpointConfig {
	node, err := lecuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (lecuo *LoginEndpointConfigUpdateOne) Exec(ctx context.Context) error {
	_, err := lecuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (lecuo *LoginEndpointConfigUpdateOne) ExecX(ctx context.Context) {
	if err := lecuo.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (lecuo *LoginEndpointConfigUpdateOne) check() error {
	if v, ok := lecuo.mutation.Endpoint(); ok {
		if err := loginendpointconfig.EndpointValidator(v); err != nil {
			return &ValidationError{Name: "endpoint", err: fmt.Errorf(`ent: validator failed for field "LoginEndpointConfig.endpoint": %w`, err)}
		}
	}
	if v, ok := lecuo.mutation.SessionTimeout(); ok {
		if err := loginendpointconfig.SessionTimeoutValidator(v); err != nil {
			return &ValidationError{Name: "session_timeout", err: fmt.Errorf(`ent: validator failed for field "LoginEndpointConfig.session_timeout": %w`, err)}
		}
	}
	if _, ok := lecuo.mutation.ServiceID(); lecuo.mutation.ServiceCleared() && !ok {
		return errors.New(`ent: clearing a required unique edge "LoginEndpointConfig.service"`)
	}
	return nil
}

func (lecuo *LoginEndpointConfigUpdateOne) sqlSave(ctx context.Context) (_node *LoginEndpointConfig, err error) {
	if err := lecuo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(loginendpointconfig.Table, loginendpointconfig.Columns, sqlgraph.NewFieldSpec(loginendpointconfig.FieldID, field.TypeString))
	id, ok := lecuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "LoginEndpointConfig.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := lecuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, loginendpointconfig.FieldID)
		for _, f := range fields {
			if !loginendpointconfig.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != loginendpointconfig.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := lecuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := lecuo.mutation.Endpoint(); ok {
		_spec.SetField(loginendpointconfig.FieldEndpoint, field.TypeString, value)
	}
	if value, ok := lecuo.mutation.SessionTimeout(); ok {
		_spec.SetField(loginendpointconfig.FieldSessionTimeout, field.TypeInt64, value)
	}
	if value, ok := lecuo.mutation.AddedSessionTimeout(); ok {
		_spec.AddField(loginendpointconfig.FieldSessionTimeout, field.TypeInt64, value)
	}
	if lecuo.mutation.ServiceCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   loginendpointconfig.ServiceTable,
			Columns: []string{loginendpointconfig.ServiceColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(service.FieldID, field.TypeString),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := lecuo.mutation.ServiceIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   loginendpointconfig.ServiceTable,
			Columns: []string{loginendpointconfig.ServiceColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(service.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &LoginEndpointConfig{config: lecuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, lecuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{loginendpointconfig.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	lecuo.mutation.done = true
	return _node, nil
}