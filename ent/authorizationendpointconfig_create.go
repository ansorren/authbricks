// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/authorizationendpointconfig"
	"go.authbricks.com/bricks/ent/service"
)

// AuthorizationEndpointConfigCreate is the builder for creating a AuthorizationEndpointConfig entity.
type AuthorizationEndpointConfigCreate struct {
	config
	mutation *AuthorizationEndpointConfigMutation
	hooks    []Hook
}

// SetEndpoint sets the "endpoint" field.
func (aecc *AuthorizationEndpointConfigCreate) SetEndpoint(s string) *AuthorizationEndpointConfigCreate {
	aecc.mutation.SetEndpoint(s)
	return aecc
}

// SetPkceRequired sets the "pkce_required" field.
func (aecc *AuthorizationEndpointConfigCreate) SetPkceRequired(b bool) *AuthorizationEndpointConfigCreate {
	aecc.mutation.SetPkceRequired(b)
	return aecc
}

// SetPkceS256CodeChallengeMethodRequired sets the "pkce_s256_code_challenge_method_required" field.
func (aecc *AuthorizationEndpointConfigCreate) SetPkceS256CodeChallengeMethodRequired(b bool) *AuthorizationEndpointConfigCreate {
	aecc.mutation.SetPkceS256CodeChallengeMethodRequired(b)
	return aecc
}

// SetID sets the "id" field.
func (aecc *AuthorizationEndpointConfigCreate) SetID(s string) *AuthorizationEndpointConfigCreate {
	aecc.mutation.SetID(s)
	return aecc
}

// SetServiceID sets the "service" edge to the Service entity by ID.
func (aecc *AuthorizationEndpointConfigCreate) SetServiceID(id string) *AuthorizationEndpointConfigCreate {
	aecc.mutation.SetServiceID(id)
	return aecc
}

// SetService sets the "service" edge to the Service entity.
func (aecc *AuthorizationEndpointConfigCreate) SetService(s *Service) *AuthorizationEndpointConfigCreate {
	return aecc.SetServiceID(s.ID)
}

// Mutation returns the AuthorizationEndpointConfigMutation object of the builder.
func (aecc *AuthorizationEndpointConfigCreate) Mutation() *AuthorizationEndpointConfigMutation {
	return aecc.mutation
}

// Save creates the AuthorizationEndpointConfig in the database.
func (aecc *AuthorizationEndpointConfigCreate) Save(ctx context.Context) (*AuthorizationEndpointConfig, error) {
	return withHooks(ctx, aecc.sqlSave, aecc.mutation, aecc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (aecc *AuthorizationEndpointConfigCreate) SaveX(ctx context.Context) *AuthorizationEndpointConfig {
	v, err := aecc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (aecc *AuthorizationEndpointConfigCreate) Exec(ctx context.Context) error {
	_, err := aecc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (aecc *AuthorizationEndpointConfigCreate) ExecX(ctx context.Context) {
	if err := aecc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (aecc *AuthorizationEndpointConfigCreate) check() error {
	if _, ok := aecc.mutation.Endpoint(); !ok {
		return &ValidationError{Name: "endpoint", err: errors.New(`ent: missing required field "AuthorizationEndpointConfig.endpoint"`)}
	}
	if v, ok := aecc.mutation.Endpoint(); ok {
		if err := authorizationendpointconfig.EndpointValidator(v); err != nil {
			return &ValidationError{Name: "endpoint", err: fmt.Errorf(`ent: validator failed for field "AuthorizationEndpointConfig.endpoint": %w`, err)}
		}
	}
	if _, ok := aecc.mutation.PkceRequired(); !ok {
		return &ValidationError{Name: "pkce_required", err: errors.New(`ent: missing required field "AuthorizationEndpointConfig.pkce_required"`)}
	}
	if _, ok := aecc.mutation.PkceS256CodeChallengeMethodRequired(); !ok {
		return &ValidationError{Name: "pkce_s256_code_challenge_method_required", err: errors.New(`ent: missing required field "AuthorizationEndpointConfig.pkce_s256_code_challenge_method_required"`)}
	}
	if v, ok := aecc.mutation.ID(); ok {
		if err := authorizationendpointconfig.IDValidator(v); err != nil {
			return &ValidationError{Name: "id", err: fmt.Errorf(`ent: validator failed for field "AuthorizationEndpointConfig.id": %w`, err)}
		}
	}
	if _, ok := aecc.mutation.ServiceID(); !ok {
		return &ValidationError{Name: "service", err: errors.New(`ent: missing required edge "AuthorizationEndpointConfig.service"`)}
	}
	return nil
}

func (aecc *AuthorizationEndpointConfigCreate) sqlSave(ctx context.Context) (*AuthorizationEndpointConfig, error) {
	if err := aecc.check(); err != nil {
		return nil, err
	}
	_node, _spec := aecc.createSpec()
	if err := sqlgraph.CreateNode(ctx, aecc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(string); ok {
			_node.ID = id
		} else {
			return nil, fmt.Errorf("unexpected AuthorizationEndpointConfig.ID type: %T", _spec.ID.Value)
		}
	}
	aecc.mutation.id = &_node.ID
	aecc.mutation.done = true
	return _node, nil
}

func (aecc *AuthorizationEndpointConfigCreate) createSpec() (*AuthorizationEndpointConfig, *sqlgraph.CreateSpec) {
	var (
		_node = &AuthorizationEndpointConfig{config: aecc.config}
		_spec = sqlgraph.NewCreateSpec(authorizationendpointconfig.Table, sqlgraph.NewFieldSpec(authorizationendpointconfig.FieldID, field.TypeString))
	)
	if id, ok := aecc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if value, ok := aecc.mutation.Endpoint(); ok {
		_spec.SetField(authorizationendpointconfig.FieldEndpoint, field.TypeString, value)
		_node.Endpoint = value
	}
	if value, ok := aecc.mutation.PkceRequired(); ok {
		_spec.SetField(authorizationendpointconfig.FieldPkceRequired, field.TypeBool, value)
		_node.PkceRequired = value
	}
	if value, ok := aecc.mutation.PkceS256CodeChallengeMethodRequired(); ok {
		_spec.SetField(authorizationendpointconfig.FieldPkceS256CodeChallengeMethodRequired, field.TypeBool, value)
		_node.PkceS256CodeChallengeMethodRequired = value
	}
	if nodes := aecc.mutation.ServiceIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   authorizationendpointconfig.ServiceTable,
			Columns: []string{authorizationendpointconfig.ServiceColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(service.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.service_service_authorization_endpoint_config = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// AuthorizationEndpointConfigCreateBulk is the builder for creating many AuthorizationEndpointConfig entities in bulk.
type AuthorizationEndpointConfigCreateBulk struct {
	config
	err      error
	builders []*AuthorizationEndpointConfigCreate
}

// Save creates the AuthorizationEndpointConfig entities in the database.
func (aeccb *AuthorizationEndpointConfigCreateBulk) Save(ctx context.Context) ([]*AuthorizationEndpointConfig, error) {
	if aeccb.err != nil {
		return nil, aeccb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(aeccb.builders))
	nodes := make([]*AuthorizationEndpointConfig, len(aeccb.builders))
	mutators := make([]Mutator, len(aeccb.builders))
	for i := range aeccb.builders {
		func(i int, root context.Context) {
			builder := aeccb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*AuthorizationEndpointConfigMutation)
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
					_, err = mutators[i+1].Mutate(root, aeccb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, aeccb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, aeccb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (aeccb *AuthorizationEndpointConfigCreateBulk) SaveX(ctx context.Context) []*AuthorizationEndpointConfig {
	v, err := aeccb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (aeccb *AuthorizationEndpointConfigCreateBulk) Exec(ctx context.Context) error {
	_, err := aeccb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (aeccb *AuthorizationEndpointConfigCreateBulk) ExecX(ctx context.Context) {
	if err := aeccb.Exec(ctx); err != nil {
		panic(err)
	}
}
