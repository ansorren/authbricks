// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/service"
	"go.authbricks.com/bricks/ent/userinfoendpointconfig"
)

// UserInfoEndpointConfigCreate is the builder for creating a UserInfoEndpointConfig entity.
type UserInfoEndpointConfigCreate struct {
	config
	mutation *UserInfoEndpointConfigMutation
	hooks    []Hook
}

// SetEndpoint sets the "endpoint" field.
func (uiecc *UserInfoEndpointConfigCreate) SetEndpoint(s string) *UserInfoEndpointConfigCreate {
	uiecc.mutation.SetEndpoint(s)
	return uiecc
}

// SetID sets the "id" field.
func (uiecc *UserInfoEndpointConfigCreate) SetID(s string) *UserInfoEndpointConfigCreate {
	uiecc.mutation.SetID(s)
	return uiecc
}

// SetServiceID sets the "service" edge to the Service entity by ID.
func (uiecc *UserInfoEndpointConfigCreate) SetServiceID(id string) *UserInfoEndpointConfigCreate {
	uiecc.mutation.SetServiceID(id)
	return uiecc
}

// SetService sets the "service" edge to the Service entity.
func (uiecc *UserInfoEndpointConfigCreate) SetService(s *Service) *UserInfoEndpointConfigCreate {
	return uiecc.SetServiceID(s.ID)
}

// Mutation returns the UserInfoEndpointConfigMutation object of the builder.
func (uiecc *UserInfoEndpointConfigCreate) Mutation() *UserInfoEndpointConfigMutation {
	return uiecc.mutation
}

// Save creates the UserInfoEndpointConfig in the database.
func (uiecc *UserInfoEndpointConfigCreate) Save(ctx context.Context) (*UserInfoEndpointConfig, error) {
	return withHooks(ctx, uiecc.sqlSave, uiecc.mutation, uiecc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (uiecc *UserInfoEndpointConfigCreate) SaveX(ctx context.Context) *UserInfoEndpointConfig {
	v, err := uiecc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (uiecc *UserInfoEndpointConfigCreate) Exec(ctx context.Context) error {
	_, err := uiecc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (uiecc *UserInfoEndpointConfigCreate) ExecX(ctx context.Context) {
	if err := uiecc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (uiecc *UserInfoEndpointConfigCreate) check() error {
	if _, ok := uiecc.mutation.Endpoint(); !ok {
		return &ValidationError{Name: "endpoint", err: errors.New(`ent: missing required field "UserInfoEndpointConfig.endpoint"`)}
	}
	if v, ok := uiecc.mutation.Endpoint(); ok {
		if err := userinfoendpointconfig.EndpointValidator(v); err != nil {
			return &ValidationError{Name: "endpoint", err: fmt.Errorf(`ent: validator failed for field "UserInfoEndpointConfig.endpoint": %w`, err)}
		}
	}
	if v, ok := uiecc.mutation.ID(); ok {
		if err := userinfoendpointconfig.IDValidator(v); err != nil {
			return &ValidationError{Name: "id", err: fmt.Errorf(`ent: validator failed for field "UserInfoEndpointConfig.id": %w`, err)}
		}
	}
	if _, ok := uiecc.mutation.ServiceID(); !ok {
		return &ValidationError{Name: "service", err: errors.New(`ent: missing required edge "UserInfoEndpointConfig.service"`)}
	}
	return nil
}

func (uiecc *UserInfoEndpointConfigCreate) sqlSave(ctx context.Context) (*UserInfoEndpointConfig, error) {
	if err := uiecc.check(); err != nil {
		return nil, err
	}
	_node, _spec := uiecc.createSpec()
	if err := sqlgraph.CreateNode(ctx, uiecc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(string); ok {
			_node.ID = id
		} else {
			return nil, fmt.Errorf("unexpected UserInfoEndpointConfig.ID type: %T", _spec.ID.Value)
		}
	}
	uiecc.mutation.id = &_node.ID
	uiecc.mutation.done = true
	return _node, nil
}

func (uiecc *UserInfoEndpointConfigCreate) createSpec() (*UserInfoEndpointConfig, *sqlgraph.CreateSpec) {
	var (
		_node = &UserInfoEndpointConfig{config: uiecc.config}
		_spec = sqlgraph.NewCreateSpec(userinfoendpointconfig.Table, sqlgraph.NewFieldSpec(userinfoendpointconfig.FieldID, field.TypeString))
	)
	if id, ok := uiecc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if value, ok := uiecc.mutation.Endpoint(); ok {
		_spec.SetField(userinfoendpointconfig.FieldEndpoint, field.TypeString, value)
		_node.Endpoint = value
	}
	if nodes := uiecc.mutation.ServiceIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   userinfoendpointconfig.ServiceTable,
			Columns: []string{userinfoendpointconfig.ServiceColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(service.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.service_service_user_info_endpoint_config = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// UserInfoEndpointConfigCreateBulk is the builder for creating many UserInfoEndpointConfig entities in bulk.
type UserInfoEndpointConfigCreateBulk struct {
	config
	err      error
	builders []*UserInfoEndpointConfigCreate
}

// Save creates the UserInfoEndpointConfig entities in the database.
func (uieccb *UserInfoEndpointConfigCreateBulk) Save(ctx context.Context) ([]*UserInfoEndpointConfig, error) {
	if uieccb.err != nil {
		return nil, uieccb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(uieccb.builders))
	nodes := make([]*UserInfoEndpointConfig, len(uieccb.builders))
	mutators := make([]Mutator, len(uieccb.builders))
	for i := range uieccb.builders {
		func(i int, root context.Context) {
			builder := uieccb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*UserInfoEndpointConfigMutation)
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
					_, err = mutators[i+1].Mutate(root, uieccb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, uieccb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, uieccb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (uieccb *UserInfoEndpointConfigCreateBulk) SaveX(ctx context.Context) []*UserInfoEndpointConfig {
	v, err := uieccb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (uieccb *UserInfoEndpointConfigCreateBulk) Exec(ctx context.Context) error {
	_, err := uieccb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (uieccb *UserInfoEndpointConfigCreateBulk) ExecX(ctx context.Context) {
	if err := uieccb.Exec(ctx); err != nil {
		panic(err)
	}
}
