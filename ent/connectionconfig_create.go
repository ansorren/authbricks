// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/connectionconfig"
	"go.authbricks.com/bricks/ent/emailpasswordconnection"
	"go.authbricks.com/bricks/ent/oidcconnection"
	"go.authbricks.com/bricks/ent/service"
)

// ConnectionConfigCreate is the builder for creating a ConnectionConfig entity.
type ConnectionConfigCreate struct {
	config
	mutation *ConnectionConfigMutation
	hooks    []Hook
}

// SetID sets the "id" field.
func (ccc *ConnectionConfigCreate) SetID(s string) *ConnectionConfigCreate {
	ccc.mutation.SetID(s)
	return ccc
}

// SetServiceID sets the "service" edge to the Service entity by ID.
func (ccc *ConnectionConfigCreate) SetServiceID(id string) *ConnectionConfigCreate {
	ccc.mutation.SetServiceID(id)
	return ccc
}

// SetService sets the "service" edge to the Service entity.
func (ccc *ConnectionConfigCreate) SetService(s *Service) *ConnectionConfigCreate {
	return ccc.SetServiceID(s.ID)
}

// AddOidcConnectionIDs adds the "oidc_connections" edge to the OIDCConnection entity by IDs.
func (ccc *ConnectionConfigCreate) AddOidcConnectionIDs(ids ...string) *ConnectionConfigCreate {
	ccc.mutation.AddOidcConnectionIDs(ids...)
	return ccc
}

// AddOidcConnections adds the "oidc_connections" edges to the OIDCConnection entity.
func (ccc *ConnectionConfigCreate) AddOidcConnections(o ...*OIDCConnection) *ConnectionConfigCreate {
	ids := make([]string, len(o))
	for i := range o {
		ids[i] = o[i].ID
	}
	return ccc.AddOidcConnectionIDs(ids...)
}

// SetEmailPasswordConnectionID sets the "email_password_connection" edge to the EmailPasswordConnection entity by ID.
func (ccc *ConnectionConfigCreate) SetEmailPasswordConnectionID(id string) *ConnectionConfigCreate {
	ccc.mutation.SetEmailPasswordConnectionID(id)
	return ccc
}

// SetNillableEmailPasswordConnectionID sets the "email_password_connection" edge to the EmailPasswordConnection entity by ID if the given value is not nil.
func (ccc *ConnectionConfigCreate) SetNillableEmailPasswordConnectionID(id *string) *ConnectionConfigCreate {
	if id != nil {
		ccc = ccc.SetEmailPasswordConnectionID(*id)
	}
	return ccc
}

// SetEmailPasswordConnection sets the "email_password_connection" edge to the EmailPasswordConnection entity.
func (ccc *ConnectionConfigCreate) SetEmailPasswordConnection(e *EmailPasswordConnection) *ConnectionConfigCreate {
	return ccc.SetEmailPasswordConnectionID(e.ID)
}

// Mutation returns the ConnectionConfigMutation object of the builder.
func (ccc *ConnectionConfigCreate) Mutation() *ConnectionConfigMutation {
	return ccc.mutation
}

// Save creates the ConnectionConfig in the database.
func (ccc *ConnectionConfigCreate) Save(ctx context.Context) (*ConnectionConfig, error) {
	return withHooks(ctx, ccc.sqlSave, ccc.mutation, ccc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (ccc *ConnectionConfigCreate) SaveX(ctx context.Context) *ConnectionConfig {
	v, err := ccc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (ccc *ConnectionConfigCreate) Exec(ctx context.Context) error {
	_, err := ccc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ccc *ConnectionConfigCreate) ExecX(ctx context.Context) {
	if err := ccc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (ccc *ConnectionConfigCreate) check() error {
	if v, ok := ccc.mutation.ID(); ok {
		if err := connectionconfig.IDValidator(v); err != nil {
			return &ValidationError{Name: "id", err: fmt.Errorf(`ent: validator failed for field "ConnectionConfig.id": %w`, err)}
		}
	}
	if _, ok := ccc.mutation.ServiceID(); !ok {
		return &ValidationError{Name: "service", err: errors.New(`ent: missing required edge "ConnectionConfig.service"`)}
	}
	return nil
}

func (ccc *ConnectionConfigCreate) sqlSave(ctx context.Context) (*ConnectionConfig, error) {
	if err := ccc.check(); err != nil {
		return nil, err
	}
	_node, _spec := ccc.createSpec()
	if err := sqlgraph.CreateNode(ctx, ccc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(string); ok {
			_node.ID = id
		} else {
			return nil, fmt.Errorf("unexpected ConnectionConfig.ID type: %T", _spec.ID.Value)
		}
	}
	ccc.mutation.id = &_node.ID
	ccc.mutation.done = true
	return _node, nil
}

func (ccc *ConnectionConfigCreate) createSpec() (*ConnectionConfig, *sqlgraph.CreateSpec) {
	var (
		_node = &ConnectionConfig{config: ccc.config}
		_spec = sqlgraph.NewCreateSpec(connectionconfig.Table, sqlgraph.NewFieldSpec(connectionconfig.FieldID, field.TypeString))
	)
	if id, ok := ccc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if nodes := ccc.mutation.ServiceIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   connectionconfig.ServiceTable,
			Columns: []string{connectionconfig.ServiceColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(service.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.service_service_connection_config = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ccc.mutation.OidcConnectionsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   connectionconfig.OidcConnectionsTable,
			Columns: []string{connectionconfig.OidcConnectionsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(oidcconnection.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ccc.mutation.EmailPasswordConnectionIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   connectionconfig.EmailPasswordConnectionTable,
			Columns: []string{connectionconfig.EmailPasswordConnectionColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(emailpasswordconnection.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// ConnectionConfigCreateBulk is the builder for creating many ConnectionConfig entities in bulk.
type ConnectionConfigCreateBulk struct {
	config
	err      error
	builders []*ConnectionConfigCreate
}

// Save creates the ConnectionConfig entities in the database.
func (cccb *ConnectionConfigCreateBulk) Save(ctx context.Context) ([]*ConnectionConfig, error) {
	if cccb.err != nil {
		return nil, cccb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(cccb.builders))
	nodes := make([]*ConnectionConfig, len(cccb.builders))
	mutators := make([]Mutator, len(cccb.builders))
	for i := range cccb.builders {
		func(i int, root context.Context) {
			builder := cccb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*ConnectionConfigMutation)
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
					_, err = mutators[i+1].Mutate(root, cccb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, cccb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, cccb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (cccb *ConnectionConfigCreateBulk) SaveX(ctx context.Context) []*ConnectionConfig {
	v, err := cccb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (cccb *ConnectionConfigCreateBulk) Exec(ctx context.Context) error {
	_, err := cccb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (cccb *ConnectionConfigCreateBulk) ExecX(ctx context.Context) {
	if err := cccb.Exec(ctx); err != nil {
		panic(err)
	}
}
