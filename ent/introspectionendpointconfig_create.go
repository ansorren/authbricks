// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/introspectionendpointconfig"
	"go.authbricks.com/bricks/ent/service"
)

// IntrospectionEndpointConfigCreate is the builder for creating a IntrospectionEndpointConfig entity.
type IntrospectionEndpointConfigCreate struct {
	config
	mutation *IntrospectionEndpointConfigMutation
	hooks    []Hook
}

// SetEndpoint sets the "endpoint" field.
func (iecc *IntrospectionEndpointConfigCreate) SetEndpoint(s string) *IntrospectionEndpointConfigCreate {
	iecc.mutation.SetEndpoint(s)
	return iecc
}

// SetID sets the "id" field.
func (iecc *IntrospectionEndpointConfigCreate) SetID(s string) *IntrospectionEndpointConfigCreate {
	iecc.mutation.SetID(s)
	return iecc
}

// SetServiceID sets the "service" edge to the Service entity by ID.
func (iecc *IntrospectionEndpointConfigCreate) SetServiceID(id string) *IntrospectionEndpointConfigCreate {
	iecc.mutation.SetServiceID(id)
	return iecc
}

// SetService sets the "service" edge to the Service entity.
func (iecc *IntrospectionEndpointConfigCreate) SetService(s *Service) *IntrospectionEndpointConfigCreate {
	return iecc.SetServiceID(s.ID)
}

// Mutation returns the IntrospectionEndpointConfigMutation object of the builder.
func (iecc *IntrospectionEndpointConfigCreate) Mutation() *IntrospectionEndpointConfigMutation {
	return iecc.mutation
}

// Save creates the IntrospectionEndpointConfig in the database.
func (iecc *IntrospectionEndpointConfigCreate) Save(ctx context.Context) (*IntrospectionEndpointConfig, error) {
	return withHooks(ctx, iecc.sqlSave, iecc.mutation, iecc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (iecc *IntrospectionEndpointConfigCreate) SaveX(ctx context.Context) *IntrospectionEndpointConfig {
	v, err := iecc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (iecc *IntrospectionEndpointConfigCreate) Exec(ctx context.Context) error {
	_, err := iecc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (iecc *IntrospectionEndpointConfigCreate) ExecX(ctx context.Context) {
	if err := iecc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (iecc *IntrospectionEndpointConfigCreate) check() error {
	if _, ok := iecc.mutation.Endpoint(); !ok {
		return &ValidationError{Name: "endpoint", err: errors.New(`ent: missing required field "IntrospectionEndpointConfig.endpoint"`)}
	}
	if v, ok := iecc.mutation.Endpoint(); ok {
		if err := introspectionendpointconfig.EndpointValidator(v); err != nil {
			return &ValidationError{Name: "endpoint", err: fmt.Errorf(`ent: validator failed for field "IntrospectionEndpointConfig.endpoint": %w`, err)}
		}
	}
	if v, ok := iecc.mutation.ID(); ok {
		if err := introspectionendpointconfig.IDValidator(v); err != nil {
			return &ValidationError{Name: "id", err: fmt.Errorf(`ent: validator failed for field "IntrospectionEndpointConfig.id": %w`, err)}
		}
	}
	if _, ok := iecc.mutation.ServiceID(); !ok {
		return &ValidationError{Name: "service", err: errors.New(`ent: missing required edge "IntrospectionEndpointConfig.service"`)}
	}
	return nil
}

func (iecc *IntrospectionEndpointConfigCreate) sqlSave(ctx context.Context) (*IntrospectionEndpointConfig, error) {
	if err := iecc.check(); err != nil {
		return nil, err
	}
	_node, _spec := iecc.createSpec()
	if err := sqlgraph.CreateNode(ctx, iecc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(string); ok {
			_node.ID = id
		} else {
			return nil, fmt.Errorf("unexpected IntrospectionEndpointConfig.ID type: %T", _spec.ID.Value)
		}
	}
	iecc.mutation.id = &_node.ID
	iecc.mutation.done = true
	return _node, nil
}

func (iecc *IntrospectionEndpointConfigCreate) createSpec() (*IntrospectionEndpointConfig, *sqlgraph.CreateSpec) {
	var (
		_node = &IntrospectionEndpointConfig{config: iecc.config}
		_spec = sqlgraph.NewCreateSpec(introspectionendpointconfig.Table, sqlgraph.NewFieldSpec(introspectionendpointconfig.FieldID, field.TypeString))
	)
	if id, ok := iecc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if value, ok := iecc.mutation.Endpoint(); ok {
		_spec.SetField(introspectionendpointconfig.FieldEndpoint, field.TypeString, value)
		_node.Endpoint = value
	}
	if nodes := iecc.mutation.ServiceIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   introspectionendpointconfig.ServiceTable,
			Columns: []string{introspectionendpointconfig.ServiceColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(service.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.service_service_introspection_endpoint_config = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// IntrospectionEndpointConfigCreateBulk is the builder for creating many IntrospectionEndpointConfig entities in bulk.
type IntrospectionEndpointConfigCreateBulk struct {
	config
	err      error
	builders []*IntrospectionEndpointConfigCreate
}

// Save creates the IntrospectionEndpointConfig entities in the database.
func (ieccb *IntrospectionEndpointConfigCreateBulk) Save(ctx context.Context) ([]*IntrospectionEndpointConfig, error) {
	if ieccb.err != nil {
		return nil, ieccb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(ieccb.builders))
	nodes := make([]*IntrospectionEndpointConfig, len(ieccb.builders))
	mutators := make([]Mutator, len(ieccb.builders))
	for i := range ieccb.builders {
		func(i int, root context.Context) {
			builder := ieccb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*IntrospectionEndpointConfigMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, ieccb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, ieccb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, ieccb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (ieccb *IntrospectionEndpointConfigCreateBulk) SaveX(ctx context.Context) []*IntrospectionEndpointConfig {
	v, err := ieccb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (ieccb *IntrospectionEndpointConfigCreateBulk) Exec(ctx context.Context) error {
	_, err := ieccb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ieccb *IntrospectionEndpointConfigCreateBulk) ExecX(ctx context.Context) {
	if err := ieccb.Exec(ctx); err != nil {
		panic(err)
	}
}
