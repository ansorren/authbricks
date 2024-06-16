// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/keyset"
	"go.authbricks.com/bricks/ent/service"
	"go.authbricks.com/bricks/ent/serviceconfig"
)

// ServiceConfigCreate is the builder for creating a ServiceConfig entity.
type ServiceConfigCreate struct {
	config
	mutation *ServiceConfigMutation
	hooks    []Hook
}

// SetID sets the "id" field.
func (scc *ServiceConfigCreate) SetID(s string) *ServiceConfigCreate {
	scc.mutation.SetID(s)
	return scc
}

// SetServiceID sets the "service" edge to the Service entity by ID.
func (scc *ServiceConfigCreate) SetServiceID(id string) *ServiceConfigCreate {
	scc.mutation.SetServiceID(id)
	return scc
}

// SetService sets the "service" edge to the Service entity.
func (scc *ServiceConfigCreate) SetService(s *Service) *ServiceConfigCreate {
	return scc.SetServiceID(s.ID)
}

// AddKeySetIDs adds the "key_sets" edge to the KeySet entity by IDs.
func (scc *ServiceConfigCreate) AddKeySetIDs(ids ...string) *ServiceConfigCreate {
	scc.mutation.AddKeySetIDs(ids...)
	return scc
}

// AddKeySets adds the "key_sets" edges to the KeySet entity.
func (scc *ServiceConfigCreate) AddKeySets(k ...*KeySet) *ServiceConfigCreate {
	ids := make([]string, len(k))
	for i := range k {
		ids[i] = k[i].ID
	}
	return scc.AddKeySetIDs(ids...)
}

// Mutation returns the ServiceConfigMutation object of the builder.
func (scc *ServiceConfigCreate) Mutation() *ServiceConfigMutation {
	return scc.mutation
}

// Save creates the ServiceConfig in the database.
func (scc *ServiceConfigCreate) Save(ctx context.Context) (*ServiceConfig, error) {
	return withHooks(ctx, scc.sqlSave, scc.mutation, scc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (scc *ServiceConfigCreate) SaveX(ctx context.Context) *ServiceConfig {
	v, err := scc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (scc *ServiceConfigCreate) Exec(ctx context.Context) error {
	_, err := scc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (scc *ServiceConfigCreate) ExecX(ctx context.Context) {
	if err := scc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (scc *ServiceConfigCreate) check() error {
	if v, ok := scc.mutation.ID(); ok {
		if err := serviceconfig.IDValidator(v); err != nil {
			return &ValidationError{Name: "id", err: fmt.Errorf(`ent: validator failed for field "ServiceConfig.id": %w`, err)}
		}
	}
	if _, ok := scc.mutation.ServiceID(); !ok {
		return &ValidationError{Name: "service", err: errors.New(`ent: missing required edge "ServiceConfig.service"`)}
	}
	return nil
}

func (scc *ServiceConfigCreate) sqlSave(ctx context.Context) (*ServiceConfig, error) {
	if err := scc.check(); err != nil {
		return nil, err
	}
	_node, _spec := scc.createSpec()
	if err := sqlgraph.CreateNode(ctx, scc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(string); ok {
			_node.ID = id
		} else {
			return nil, fmt.Errorf("unexpected ServiceConfig.ID type: %T", _spec.ID.Value)
		}
	}
	scc.mutation.id = &_node.ID
	scc.mutation.done = true
	return _node, nil
}

func (scc *ServiceConfigCreate) createSpec() (*ServiceConfig, *sqlgraph.CreateSpec) {
	var (
		_node = &ServiceConfig{config: scc.config}
		_spec = sqlgraph.NewCreateSpec(serviceconfig.Table, sqlgraph.NewFieldSpec(serviceconfig.FieldID, field.TypeString))
	)
	if id, ok := scc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if nodes := scc.mutation.ServiceIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   serviceconfig.ServiceTable,
			Columns: []string{serviceconfig.ServiceColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(service.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.service_service_config = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := scc.mutation.KeySetsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   serviceconfig.KeySetsTable,
			Columns: []string{serviceconfig.KeySetsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(keyset.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// ServiceConfigCreateBulk is the builder for creating many ServiceConfig entities in bulk.
type ServiceConfigCreateBulk struct {
	config
	err      error
	builders []*ServiceConfigCreate
}

// Save creates the ServiceConfig entities in the database.
func (sccb *ServiceConfigCreateBulk) Save(ctx context.Context) ([]*ServiceConfig, error) {
	if sccb.err != nil {
		return nil, sccb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(sccb.builders))
	nodes := make([]*ServiceConfig, len(sccb.builders))
	mutators := make([]Mutator, len(sccb.builders))
	for i := range sccb.builders {
		func(i int, root context.Context) {
			builder := sccb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*ServiceConfigMutation)
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
					_, err = mutators[i+1].Mutate(root, sccb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, sccb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, sccb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (sccb *ServiceConfigCreateBulk) SaveX(ctx context.Context) []*ServiceConfig {
	v, err := sccb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (sccb *ServiceConfigCreateBulk) Exec(ctx context.Context) error {
	_, err := sccb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (sccb *ServiceConfigCreateBulk) ExecX(ctx context.Context) {
	if err := sccb.Exec(ctx); err != nil {
		panic(err)
	}
}