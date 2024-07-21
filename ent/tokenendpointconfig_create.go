// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/service"
	"go.authbricks.com/bricks/ent/tokenendpointconfig"
)

// TokenEndpointConfigCreate is the builder for creating a TokenEndpointConfig entity.
type TokenEndpointConfigCreate struct {
	config
	mutation *TokenEndpointConfigMutation
	hooks    []Hook
}

// SetEndpoint sets the "endpoint" field.
func (tecc *TokenEndpointConfigCreate) SetEndpoint(s string) *TokenEndpointConfigCreate {
	tecc.mutation.SetEndpoint(s)
	return tecc
}

// SetAllowedAuthenticationMethods sets the "allowed_authentication_methods" field.
func (tecc *TokenEndpointConfigCreate) SetAllowedAuthenticationMethods(s []string) *TokenEndpointConfigCreate {
	tecc.mutation.SetAllowedAuthenticationMethods(s)
	return tecc
}

// SetID sets the "id" field.
func (tecc *TokenEndpointConfigCreate) SetID(s string) *TokenEndpointConfigCreate {
	tecc.mutation.SetID(s)
	return tecc
}

// SetServiceID sets the "service" edge to the Service entity by ID.
func (tecc *TokenEndpointConfigCreate) SetServiceID(id string) *TokenEndpointConfigCreate {
	tecc.mutation.SetServiceID(id)
	return tecc
}

// SetService sets the "service" edge to the Service entity.
func (tecc *TokenEndpointConfigCreate) SetService(s *Service) *TokenEndpointConfigCreate {
	return tecc.SetServiceID(s.ID)
}

// Mutation returns the TokenEndpointConfigMutation object of the builder.
func (tecc *TokenEndpointConfigCreate) Mutation() *TokenEndpointConfigMutation {
	return tecc.mutation
}

// Save creates the TokenEndpointConfig in the database.
func (tecc *TokenEndpointConfigCreate) Save(ctx context.Context) (*TokenEndpointConfig, error) {
	return withHooks(ctx, tecc.sqlSave, tecc.mutation, tecc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (tecc *TokenEndpointConfigCreate) SaveX(ctx context.Context) *TokenEndpointConfig {
	v, err := tecc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (tecc *TokenEndpointConfigCreate) Exec(ctx context.Context) error {
	_, err := tecc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (tecc *TokenEndpointConfigCreate) ExecX(ctx context.Context) {
	if err := tecc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (tecc *TokenEndpointConfigCreate) check() error {
	if _, ok := tecc.mutation.Endpoint(); !ok {
		return &ValidationError{Name: "endpoint", err: errors.New(`ent: missing required field "TokenEndpointConfig.endpoint"`)}
	}
	if v, ok := tecc.mutation.Endpoint(); ok {
		if err := tokenendpointconfig.EndpointValidator(v); err != nil {
			return &ValidationError{Name: "endpoint", err: fmt.Errorf(`ent: validator failed for field "TokenEndpointConfig.endpoint": %w`, err)}
		}
	}
	if _, ok := tecc.mutation.AllowedAuthenticationMethods(); !ok {
		return &ValidationError{Name: "allowed_authentication_methods", err: errors.New(`ent: missing required field "TokenEndpointConfig.allowed_authentication_methods"`)}
	}
	if v, ok := tecc.mutation.ID(); ok {
		if err := tokenendpointconfig.IDValidator(v); err != nil {
			return &ValidationError{Name: "id", err: fmt.Errorf(`ent: validator failed for field "TokenEndpointConfig.id": %w`, err)}
		}
	}
	if _, ok := tecc.mutation.ServiceID(); !ok {
		return &ValidationError{Name: "service", err: errors.New(`ent: missing required edge "TokenEndpointConfig.service"`)}
	}
	return nil
}

func (tecc *TokenEndpointConfigCreate) sqlSave(ctx context.Context) (*TokenEndpointConfig, error) {
	if err := tecc.check(); err != nil {
		return nil, err
	}
	_node, _spec := tecc.createSpec()
	if err := sqlgraph.CreateNode(ctx, tecc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(string); ok {
			_node.ID = id
		} else {
			return nil, fmt.Errorf("unexpected TokenEndpointConfig.ID type: %T", _spec.ID.Value)
		}
	}
	tecc.mutation.id = &_node.ID
	tecc.mutation.done = true
	return _node, nil
}

func (tecc *TokenEndpointConfigCreate) createSpec() (*TokenEndpointConfig, *sqlgraph.CreateSpec) {
	var (
		_node = &TokenEndpointConfig{config: tecc.config}
		_spec = sqlgraph.NewCreateSpec(tokenendpointconfig.Table, sqlgraph.NewFieldSpec(tokenendpointconfig.FieldID, field.TypeString))
	)
	if id, ok := tecc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if value, ok := tecc.mutation.Endpoint(); ok {
		_spec.SetField(tokenendpointconfig.FieldEndpoint, field.TypeString, value)
		_node.Endpoint = value
	}
	if value, ok := tecc.mutation.AllowedAuthenticationMethods(); ok {
		_spec.SetField(tokenendpointconfig.FieldAllowedAuthenticationMethods, field.TypeJSON, value)
		_node.AllowedAuthenticationMethods = value
	}
	if nodes := tecc.mutation.ServiceIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   tokenendpointconfig.ServiceTable,
			Columns: []string{tokenendpointconfig.ServiceColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(service.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.service_service_token_endpoint_config = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// TokenEndpointConfigCreateBulk is the builder for creating many TokenEndpointConfig entities in bulk.
type TokenEndpointConfigCreateBulk struct {
	config
	err      error
	builders []*TokenEndpointConfigCreate
}

// Save creates the TokenEndpointConfig entities in the database.
func (teccb *TokenEndpointConfigCreateBulk) Save(ctx context.Context) ([]*TokenEndpointConfig, error) {
	if teccb.err != nil {
		return nil, teccb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(teccb.builders))
	nodes := make([]*TokenEndpointConfig, len(teccb.builders))
	mutators := make([]Mutator, len(teccb.builders))
	for i := range teccb.builders {
		func(i int, root context.Context) {
			builder := teccb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*TokenEndpointConfigMutation)
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
					_, err = mutators[i+1].Mutate(root, teccb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, teccb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, teccb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (teccb *TokenEndpointConfigCreateBulk) SaveX(ctx context.Context) []*TokenEndpointConfig {
	v, err := teccb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (teccb *TokenEndpointConfigCreateBulk) Exec(ctx context.Context) error {
	_, err := teccb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (teccb *TokenEndpointConfigCreateBulk) ExecX(ctx context.Context) {
	if err := teccb.Exec(ctx); err != nil {
		panic(err)
	}
}
