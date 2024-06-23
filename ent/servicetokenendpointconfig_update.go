// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/dialect/sql/sqljson"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/predicate"
	"go.authbricks.com/bricks/ent/service"
	"go.authbricks.com/bricks/ent/servicetokenendpointconfig"
)

// ServiceTokenEndpointConfigUpdate is the builder for updating ServiceTokenEndpointConfig entities.
type ServiceTokenEndpointConfigUpdate struct {
	config
	hooks    []Hook
	mutation *ServiceTokenEndpointConfigMutation
}

// Where appends a list predicates to the ServiceTokenEndpointConfigUpdate builder.
func (stecu *ServiceTokenEndpointConfigUpdate) Where(ps ...predicate.ServiceTokenEndpointConfig) *ServiceTokenEndpointConfigUpdate {
	stecu.mutation.Where(ps...)
	return stecu
}

// SetEndpoint sets the "endpoint" field.
func (stecu *ServiceTokenEndpointConfigUpdate) SetEndpoint(s string) *ServiceTokenEndpointConfigUpdate {
	stecu.mutation.SetEndpoint(s)
	return stecu
}

// SetNillableEndpoint sets the "endpoint" field if the given value is not nil.
func (stecu *ServiceTokenEndpointConfigUpdate) SetNillableEndpoint(s *string) *ServiceTokenEndpointConfigUpdate {
	if s != nil {
		stecu.SetEndpoint(*s)
	}
	return stecu
}

// SetAllowedAuthenticationMethods sets the "allowed_authentication_methods" field.
func (stecu *ServiceTokenEndpointConfigUpdate) SetAllowedAuthenticationMethods(s []string) *ServiceTokenEndpointConfigUpdate {
	stecu.mutation.SetAllowedAuthenticationMethods(s)
	return stecu
}

// AppendAllowedAuthenticationMethods appends s to the "allowed_authentication_methods" field.
func (stecu *ServiceTokenEndpointConfigUpdate) AppendAllowedAuthenticationMethods(s []string) *ServiceTokenEndpointConfigUpdate {
	stecu.mutation.AppendAllowedAuthenticationMethods(s)
	return stecu
}

// SetServiceID sets the "service" edge to the Service entity by ID.
func (stecu *ServiceTokenEndpointConfigUpdate) SetServiceID(id string) *ServiceTokenEndpointConfigUpdate {
	stecu.mutation.SetServiceID(id)
	return stecu
}

// SetService sets the "service" edge to the Service entity.
func (stecu *ServiceTokenEndpointConfigUpdate) SetService(s *Service) *ServiceTokenEndpointConfigUpdate {
	return stecu.SetServiceID(s.ID)
}

// Mutation returns the ServiceTokenEndpointConfigMutation object of the builder.
func (stecu *ServiceTokenEndpointConfigUpdate) Mutation() *ServiceTokenEndpointConfigMutation {
	return stecu.mutation
}

// ClearService clears the "service" edge to the Service entity.
func (stecu *ServiceTokenEndpointConfigUpdate) ClearService() *ServiceTokenEndpointConfigUpdate {
	stecu.mutation.ClearService()
	return stecu
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (stecu *ServiceTokenEndpointConfigUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, stecu.sqlSave, stecu.mutation, stecu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (stecu *ServiceTokenEndpointConfigUpdate) SaveX(ctx context.Context) int {
	affected, err := stecu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (stecu *ServiceTokenEndpointConfigUpdate) Exec(ctx context.Context) error {
	_, err := stecu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (stecu *ServiceTokenEndpointConfigUpdate) ExecX(ctx context.Context) {
	if err := stecu.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (stecu *ServiceTokenEndpointConfigUpdate) check() error {
	if v, ok := stecu.mutation.Endpoint(); ok {
		if err := servicetokenendpointconfig.EndpointValidator(v); err != nil {
			return &ValidationError{Name: "endpoint", err: fmt.Errorf(`ent: validator failed for field "ServiceTokenEndpointConfig.endpoint": %w`, err)}
		}
	}
	if _, ok := stecu.mutation.ServiceID(); stecu.mutation.ServiceCleared() && !ok {
		return errors.New(`ent: clearing a required unique edge "ServiceTokenEndpointConfig.service"`)
	}
	return nil
}

func (stecu *ServiceTokenEndpointConfigUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := stecu.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(servicetokenendpointconfig.Table, servicetokenendpointconfig.Columns, sqlgraph.NewFieldSpec(servicetokenendpointconfig.FieldID, field.TypeString))
	if ps := stecu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := stecu.mutation.Endpoint(); ok {
		_spec.SetField(servicetokenendpointconfig.FieldEndpoint, field.TypeString, value)
	}
	if value, ok := stecu.mutation.AllowedAuthenticationMethods(); ok {
		_spec.SetField(servicetokenendpointconfig.FieldAllowedAuthenticationMethods, field.TypeJSON, value)
	}
	if value, ok := stecu.mutation.AppendedAllowedAuthenticationMethods(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, servicetokenendpointconfig.FieldAllowedAuthenticationMethods, value)
		})
	}
	if stecu.mutation.ServiceCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   servicetokenendpointconfig.ServiceTable,
			Columns: []string{servicetokenendpointconfig.ServiceColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(service.FieldID, field.TypeString),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := stecu.mutation.ServiceIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   servicetokenendpointconfig.ServiceTable,
			Columns: []string{servicetokenendpointconfig.ServiceColumn},
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
	if n, err = sqlgraph.UpdateNodes(ctx, stecu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{servicetokenendpointconfig.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	stecu.mutation.done = true
	return n, nil
}

// ServiceTokenEndpointConfigUpdateOne is the builder for updating a single ServiceTokenEndpointConfig entity.
type ServiceTokenEndpointConfigUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *ServiceTokenEndpointConfigMutation
}

// SetEndpoint sets the "endpoint" field.
func (stecuo *ServiceTokenEndpointConfigUpdateOne) SetEndpoint(s string) *ServiceTokenEndpointConfigUpdateOne {
	stecuo.mutation.SetEndpoint(s)
	return stecuo
}

// SetNillableEndpoint sets the "endpoint" field if the given value is not nil.
func (stecuo *ServiceTokenEndpointConfigUpdateOne) SetNillableEndpoint(s *string) *ServiceTokenEndpointConfigUpdateOne {
	if s != nil {
		stecuo.SetEndpoint(*s)
	}
	return stecuo
}

// SetAllowedAuthenticationMethods sets the "allowed_authentication_methods" field.
func (stecuo *ServiceTokenEndpointConfigUpdateOne) SetAllowedAuthenticationMethods(s []string) *ServiceTokenEndpointConfigUpdateOne {
	stecuo.mutation.SetAllowedAuthenticationMethods(s)
	return stecuo
}

// AppendAllowedAuthenticationMethods appends s to the "allowed_authentication_methods" field.
func (stecuo *ServiceTokenEndpointConfigUpdateOne) AppendAllowedAuthenticationMethods(s []string) *ServiceTokenEndpointConfigUpdateOne {
	stecuo.mutation.AppendAllowedAuthenticationMethods(s)
	return stecuo
}

// SetServiceID sets the "service" edge to the Service entity by ID.
func (stecuo *ServiceTokenEndpointConfigUpdateOne) SetServiceID(id string) *ServiceTokenEndpointConfigUpdateOne {
	stecuo.mutation.SetServiceID(id)
	return stecuo
}

// SetService sets the "service" edge to the Service entity.
func (stecuo *ServiceTokenEndpointConfigUpdateOne) SetService(s *Service) *ServiceTokenEndpointConfigUpdateOne {
	return stecuo.SetServiceID(s.ID)
}

// Mutation returns the ServiceTokenEndpointConfigMutation object of the builder.
func (stecuo *ServiceTokenEndpointConfigUpdateOne) Mutation() *ServiceTokenEndpointConfigMutation {
	return stecuo.mutation
}

// ClearService clears the "service" edge to the Service entity.
func (stecuo *ServiceTokenEndpointConfigUpdateOne) ClearService() *ServiceTokenEndpointConfigUpdateOne {
	stecuo.mutation.ClearService()
	return stecuo
}

// Where appends a list predicates to the ServiceTokenEndpointConfigUpdate builder.
func (stecuo *ServiceTokenEndpointConfigUpdateOne) Where(ps ...predicate.ServiceTokenEndpointConfig) *ServiceTokenEndpointConfigUpdateOne {
	stecuo.mutation.Where(ps...)
	return stecuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (stecuo *ServiceTokenEndpointConfigUpdateOne) Select(field string, fields ...string) *ServiceTokenEndpointConfigUpdateOne {
	stecuo.fields = append([]string{field}, fields...)
	return stecuo
}

// Save executes the query and returns the updated ServiceTokenEndpointConfig entity.
func (stecuo *ServiceTokenEndpointConfigUpdateOne) Save(ctx context.Context) (*ServiceTokenEndpointConfig, error) {
	return withHooks(ctx, stecuo.sqlSave, stecuo.mutation, stecuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (stecuo *ServiceTokenEndpointConfigUpdateOne) SaveX(ctx context.Context) *ServiceTokenEndpointConfig {
	node, err := stecuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (stecuo *ServiceTokenEndpointConfigUpdateOne) Exec(ctx context.Context) error {
	_, err := stecuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (stecuo *ServiceTokenEndpointConfigUpdateOne) ExecX(ctx context.Context) {
	if err := stecuo.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (stecuo *ServiceTokenEndpointConfigUpdateOne) check() error {
	if v, ok := stecuo.mutation.Endpoint(); ok {
		if err := servicetokenendpointconfig.EndpointValidator(v); err != nil {
			return &ValidationError{Name: "endpoint", err: fmt.Errorf(`ent: validator failed for field "ServiceTokenEndpointConfig.endpoint": %w`, err)}
		}
	}
	if _, ok := stecuo.mutation.ServiceID(); stecuo.mutation.ServiceCleared() && !ok {
		return errors.New(`ent: clearing a required unique edge "ServiceTokenEndpointConfig.service"`)
	}
	return nil
}

func (stecuo *ServiceTokenEndpointConfigUpdateOne) sqlSave(ctx context.Context) (_node *ServiceTokenEndpointConfig, err error) {
	if err := stecuo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(servicetokenendpointconfig.Table, servicetokenendpointconfig.Columns, sqlgraph.NewFieldSpec(servicetokenendpointconfig.FieldID, field.TypeString))
	id, ok := stecuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "ServiceTokenEndpointConfig.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := stecuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, servicetokenendpointconfig.FieldID)
		for _, f := range fields {
			if !servicetokenendpointconfig.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != servicetokenendpointconfig.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := stecuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := stecuo.mutation.Endpoint(); ok {
		_spec.SetField(servicetokenendpointconfig.FieldEndpoint, field.TypeString, value)
	}
	if value, ok := stecuo.mutation.AllowedAuthenticationMethods(); ok {
		_spec.SetField(servicetokenendpointconfig.FieldAllowedAuthenticationMethods, field.TypeJSON, value)
	}
	if value, ok := stecuo.mutation.AppendedAllowedAuthenticationMethods(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, servicetokenendpointconfig.FieldAllowedAuthenticationMethods, value)
		})
	}
	if stecuo.mutation.ServiceCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   servicetokenendpointconfig.ServiceTable,
			Columns: []string{servicetokenendpointconfig.ServiceColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(service.FieldID, field.TypeString),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := stecuo.mutation.ServiceIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   servicetokenendpointconfig.ServiceTable,
			Columns: []string{servicetokenendpointconfig.ServiceColumn},
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
	_node = &ServiceTokenEndpointConfig{config: stecuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, stecuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{servicetokenendpointconfig.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	stecuo.mutation.done = true
	return _node, nil
}