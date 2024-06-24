// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/application"
	"go.authbricks.com/bricks/ent/keyset"
	"go.authbricks.com/bricks/ent/service"
	"go.authbricks.com/bricks/ent/serviceauthorizationendpointconfig"
	"go.authbricks.com/bricks/ent/serviceintrospectionendpointconfig"
	"go.authbricks.com/bricks/ent/servicejwksendpointconfig"
	"go.authbricks.com/bricks/ent/servicetokenendpointconfig"
	"go.authbricks.com/bricks/ent/serviceuserinfoendpointconfig"
)

// ServiceCreate is the builder for creating a Service entity.
type ServiceCreate struct {
	config
	mutation *ServiceMutation
	hooks    []Hook
}

// SetName sets the "name" field.
func (sc *ServiceCreate) SetName(s string) *ServiceCreate {
	sc.mutation.SetName(s)
	return sc
}

// SetIssuer sets the "issuer" field.
func (sc *ServiceCreate) SetIssuer(s string) *ServiceCreate {
	sc.mutation.SetIssuer(s)
	return sc
}

// SetDescription sets the "description" field.
func (sc *ServiceCreate) SetDescription(s string) *ServiceCreate {
	sc.mutation.SetDescription(s)
	return sc
}

// SetScopes sets the "scopes" field.
func (sc *ServiceCreate) SetScopes(s []string) *ServiceCreate {
	sc.mutation.SetScopes(s)
	return sc
}

// SetServiceMetadata sets the "service_metadata" field.
func (sc *ServiceCreate) SetServiceMetadata(s string) *ServiceCreate {
	sc.mutation.SetServiceMetadata(s)
	return sc
}

// SetAllowedClientMetadata sets the "allowed_client_metadata" field.
func (sc *ServiceCreate) SetAllowedClientMetadata(s []string) *ServiceCreate {
	sc.mutation.SetAllowedClientMetadata(s)
	return sc
}

// SetGrantTypes sets the "grant_types" field.
func (sc *ServiceCreate) SetGrantTypes(s []string) *ServiceCreate {
	sc.mutation.SetGrantTypes(s)
	return sc
}

// SetResponseTypes sets the "response_types" field.
func (sc *ServiceCreate) SetResponseTypes(s []string) *ServiceCreate {
	sc.mutation.SetResponseTypes(s)
	return sc
}

// SetID sets the "id" field.
func (sc *ServiceCreate) SetID(s string) *ServiceCreate {
	sc.mutation.SetID(s)
	return sc
}

// SetKeySetID sets the "key_set" edge to the KeySet entity by ID.
func (sc *ServiceCreate) SetKeySetID(id string) *ServiceCreate {
	sc.mutation.SetKeySetID(id)
	return sc
}

// SetNillableKeySetID sets the "key_set" edge to the KeySet entity by ID if the given value is not nil.
func (sc *ServiceCreate) SetNillableKeySetID(id *string) *ServiceCreate {
	if id != nil {
		sc = sc.SetKeySetID(*id)
	}
	return sc
}

// SetKeySet sets the "key_set" edge to the KeySet entity.
func (sc *ServiceCreate) SetKeySet(k *KeySet) *ServiceCreate {
	return sc.SetKeySetID(k.ID)
}

// SetServiceAuthorizationEndpointConfigID sets the "service_authorization_endpoint_config" edge to the ServiceAuthorizationEndpointConfig entity by ID.
func (sc *ServiceCreate) SetServiceAuthorizationEndpointConfigID(id string) *ServiceCreate {
	sc.mutation.SetServiceAuthorizationEndpointConfigID(id)
	return sc
}

// SetNillableServiceAuthorizationEndpointConfigID sets the "service_authorization_endpoint_config" edge to the ServiceAuthorizationEndpointConfig entity by ID if the given value is not nil.
func (sc *ServiceCreate) SetNillableServiceAuthorizationEndpointConfigID(id *string) *ServiceCreate {
	if id != nil {
		sc = sc.SetServiceAuthorizationEndpointConfigID(*id)
	}
	return sc
}

// SetServiceAuthorizationEndpointConfig sets the "service_authorization_endpoint_config" edge to the ServiceAuthorizationEndpointConfig entity.
func (sc *ServiceCreate) SetServiceAuthorizationEndpointConfig(s *ServiceAuthorizationEndpointConfig) *ServiceCreate {
	return sc.SetServiceAuthorizationEndpointConfigID(s.ID)
}

// SetServiceIntrospectionEndpointConfigID sets the "service_introspection_endpoint_config" edge to the ServiceIntrospectionEndpointConfig entity by ID.
func (sc *ServiceCreate) SetServiceIntrospectionEndpointConfigID(id string) *ServiceCreate {
	sc.mutation.SetServiceIntrospectionEndpointConfigID(id)
	return sc
}

// SetNillableServiceIntrospectionEndpointConfigID sets the "service_introspection_endpoint_config" edge to the ServiceIntrospectionEndpointConfig entity by ID if the given value is not nil.
func (sc *ServiceCreate) SetNillableServiceIntrospectionEndpointConfigID(id *string) *ServiceCreate {
	if id != nil {
		sc = sc.SetServiceIntrospectionEndpointConfigID(*id)
	}
	return sc
}

// SetServiceIntrospectionEndpointConfig sets the "service_introspection_endpoint_config" edge to the ServiceIntrospectionEndpointConfig entity.
func (sc *ServiceCreate) SetServiceIntrospectionEndpointConfig(s *ServiceIntrospectionEndpointConfig) *ServiceCreate {
	return sc.SetServiceIntrospectionEndpointConfigID(s.ID)
}

// SetServiceTokenEndpointConfigID sets the "service_token_endpoint_config" edge to the ServiceTokenEndpointConfig entity by ID.
func (sc *ServiceCreate) SetServiceTokenEndpointConfigID(id string) *ServiceCreate {
	sc.mutation.SetServiceTokenEndpointConfigID(id)
	return sc
}

// SetNillableServiceTokenEndpointConfigID sets the "service_token_endpoint_config" edge to the ServiceTokenEndpointConfig entity by ID if the given value is not nil.
func (sc *ServiceCreate) SetNillableServiceTokenEndpointConfigID(id *string) *ServiceCreate {
	if id != nil {
		sc = sc.SetServiceTokenEndpointConfigID(*id)
	}
	return sc
}

// SetServiceTokenEndpointConfig sets the "service_token_endpoint_config" edge to the ServiceTokenEndpointConfig entity.
func (sc *ServiceCreate) SetServiceTokenEndpointConfig(s *ServiceTokenEndpointConfig) *ServiceCreate {
	return sc.SetServiceTokenEndpointConfigID(s.ID)
}

// SetServiceUserInfoEndpointConfigID sets the "service_user_info_endpoint_config" edge to the ServiceUserInfoEndpointConfig entity by ID.
func (sc *ServiceCreate) SetServiceUserInfoEndpointConfigID(id string) *ServiceCreate {
	sc.mutation.SetServiceUserInfoEndpointConfigID(id)
	return sc
}

// SetNillableServiceUserInfoEndpointConfigID sets the "service_user_info_endpoint_config" edge to the ServiceUserInfoEndpointConfig entity by ID if the given value is not nil.
func (sc *ServiceCreate) SetNillableServiceUserInfoEndpointConfigID(id *string) *ServiceCreate {
	if id != nil {
		sc = sc.SetServiceUserInfoEndpointConfigID(*id)
	}
	return sc
}

// SetServiceUserInfoEndpointConfig sets the "service_user_info_endpoint_config" edge to the ServiceUserInfoEndpointConfig entity.
func (sc *ServiceCreate) SetServiceUserInfoEndpointConfig(s *ServiceUserInfoEndpointConfig) *ServiceCreate {
	return sc.SetServiceUserInfoEndpointConfigID(s.ID)
}

// SetServiceJwksEndpointConfigID sets the "service_jwks_endpoint_config" edge to the ServiceJWKSEndpointConfig entity by ID.
func (sc *ServiceCreate) SetServiceJwksEndpointConfigID(id string) *ServiceCreate {
	sc.mutation.SetServiceJwksEndpointConfigID(id)
	return sc
}

// SetNillableServiceJwksEndpointConfigID sets the "service_jwks_endpoint_config" edge to the ServiceJWKSEndpointConfig entity by ID if the given value is not nil.
func (sc *ServiceCreate) SetNillableServiceJwksEndpointConfigID(id *string) *ServiceCreate {
	if id != nil {
		sc = sc.SetServiceJwksEndpointConfigID(*id)
	}
	return sc
}

// SetServiceJwksEndpointConfig sets the "service_jwks_endpoint_config" edge to the ServiceJWKSEndpointConfig entity.
func (sc *ServiceCreate) SetServiceJwksEndpointConfig(s *ServiceJWKSEndpointConfig) *ServiceCreate {
	return sc.SetServiceJwksEndpointConfigID(s.ID)
}

// AddApplicationIDs adds the "applications" edge to the Application entity by IDs.
func (sc *ServiceCreate) AddApplicationIDs(ids ...string) *ServiceCreate {
	sc.mutation.AddApplicationIDs(ids...)
	return sc
}

// AddApplications adds the "applications" edges to the Application entity.
func (sc *ServiceCreate) AddApplications(a ...*Application) *ServiceCreate {
	ids := make([]string, len(a))
	for i := range a {
		ids[i] = a[i].ID
	}
	return sc.AddApplicationIDs(ids...)
}

// Mutation returns the ServiceMutation object of the builder.
func (sc *ServiceCreate) Mutation() *ServiceMutation {
	return sc.mutation
}

// Save creates the Service in the database.
func (sc *ServiceCreate) Save(ctx context.Context) (*Service, error) {
	return withHooks(ctx, sc.sqlSave, sc.mutation, sc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (sc *ServiceCreate) SaveX(ctx context.Context) *Service {
	v, err := sc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (sc *ServiceCreate) Exec(ctx context.Context) error {
	_, err := sc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (sc *ServiceCreate) ExecX(ctx context.Context) {
	if err := sc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (sc *ServiceCreate) check() error {
	if _, ok := sc.mutation.Name(); !ok {
		return &ValidationError{Name: "name", err: errors.New(`ent: missing required field "Service.name"`)}
	}
	if v, ok := sc.mutation.Name(); ok {
		if err := service.NameValidator(v); err != nil {
			return &ValidationError{Name: "name", err: fmt.Errorf(`ent: validator failed for field "Service.name": %w`, err)}
		}
	}
	if _, ok := sc.mutation.Issuer(); !ok {
		return &ValidationError{Name: "issuer", err: errors.New(`ent: missing required field "Service.issuer"`)}
	}
	if v, ok := sc.mutation.Issuer(); ok {
		if err := service.IssuerValidator(v); err != nil {
			return &ValidationError{Name: "issuer", err: fmt.Errorf(`ent: validator failed for field "Service.issuer": %w`, err)}
		}
	}
	if _, ok := sc.mutation.Description(); !ok {
		return &ValidationError{Name: "description", err: errors.New(`ent: missing required field "Service.description"`)}
	}
	if _, ok := sc.mutation.Scopes(); !ok {
		return &ValidationError{Name: "scopes", err: errors.New(`ent: missing required field "Service.scopes"`)}
	}
	if _, ok := sc.mutation.ServiceMetadata(); !ok {
		return &ValidationError{Name: "service_metadata", err: errors.New(`ent: missing required field "Service.service_metadata"`)}
	}
	if _, ok := sc.mutation.AllowedClientMetadata(); !ok {
		return &ValidationError{Name: "allowed_client_metadata", err: errors.New(`ent: missing required field "Service.allowed_client_metadata"`)}
	}
	if _, ok := sc.mutation.GrantTypes(); !ok {
		return &ValidationError{Name: "grant_types", err: errors.New(`ent: missing required field "Service.grant_types"`)}
	}
	if _, ok := sc.mutation.ResponseTypes(); !ok {
		return &ValidationError{Name: "response_types", err: errors.New(`ent: missing required field "Service.response_types"`)}
	}
	if v, ok := sc.mutation.ID(); ok {
		if err := service.IDValidator(v); err != nil {
			return &ValidationError{Name: "id", err: fmt.Errorf(`ent: validator failed for field "Service.id": %w`, err)}
		}
	}
	return nil
}

func (sc *ServiceCreate) sqlSave(ctx context.Context) (*Service, error) {
	if err := sc.check(); err != nil {
		return nil, err
	}
	_node, _spec := sc.createSpec()
	if err := sqlgraph.CreateNode(ctx, sc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(string); ok {
			_node.ID = id
		} else {
			return nil, fmt.Errorf("unexpected Service.ID type: %T", _spec.ID.Value)
		}
	}
	sc.mutation.id = &_node.ID
	sc.mutation.done = true
	return _node, nil
}

func (sc *ServiceCreate) createSpec() (*Service, *sqlgraph.CreateSpec) {
	var (
		_node = &Service{config: sc.config}
		_spec = sqlgraph.NewCreateSpec(service.Table, sqlgraph.NewFieldSpec(service.FieldID, field.TypeString))
	)
	if id, ok := sc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if value, ok := sc.mutation.Name(); ok {
		_spec.SetField(service.FieldName, field.TypeString, value)
		_node.Name = value
	}
	if value, ok := sc.mutation.Issuer(); ok {
		_spec.SetField(service.FieldIssuer, field.TypeString, value)
		_node.Issuer = value
	}
	if value, ok := sc.mutation.Description(); ok {
		_spec.SetField(service.FieldDescription, field.TypeString, value)
		_node.Description = value
	}
	if value, ok := sc.mutation.Scopes(); ok {
		_spec.SetField(service.FieldScopes, field.TypeJSON, value)
		_node.Scopes = value
	}
	if value, ok := sc.mutation.ServiceMetadata(); ok {
		_spec.SetField(service.FieldServiceMetadata, field.TypeString, value)
		_node.ServiceMetadata = value
	}
	if value, ok := sc.mutation.AllowedClientMetadata(); ok {
		_spec.SetField(service.FieldAllowedClientMetadata, field.TypeJSON, value)
		_node.AllowedClientMetadata = value
	}
	if value, ok := sc.mutation.GrantTypes(); ok {
		_spec.SetField(service.FieldGrantTypes, field.TypeJSON, value)
		_node.GrantTypes = value
	}
	if value, ok := sc.mutation.ResponseTypes(); ok {
		_spec.SetField(service.FieldResponseTypes, field.TypeJSON, value)
		_node.ResponseTypes = value
	}
	if nodes := sc.mutation.KeySetIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   service.KeySetTable,
			Columns: []string{service.KeySetColumn},
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
	if nodes := sc.mutation.ServiceAuthorizationEndpointConfigIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   service.ServiceAuthorizationEndpointConfigTable,
			Columns: []string{service.ServiceAuthorizationEndpointConfigColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(serviceauthorizationendpointconfig.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := sc.mutation.ServiceIntrospectionEndpointConfigIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   service.ServiceIntrospectionEndpointConfigTable,
			Columns: []string{service.ServiceIntrospectionEndpointConfigColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(serviceintrospectionendpointconfig.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := sc.mutation.ServiceTokenEndpointConfigIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   service.ServiceTokenEndpointConfigTable,
			Columns: []string{service.ServiceTokenEndpointConfigColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(servicetokenendpointconfig.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := sc.mutation.ServiceUserInfoEndpointConfigIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   service.ServiceUserInfoEndpointConfigTable,
			Columns: []string{service.ServiceUserInfoEndpointConfigColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(serviceuserinfoendpointconfig.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := sc.mutation.ServiceJwksEndpointConfigIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   service.ServiceJwksEndpointConfigTable,
			Columns: []string{service.ServiceJwksEndpointConfigColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(servicejwksendpointconfig.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := sc.mutation.ApplicationsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   service.ApplicationsTable,
			Columns: []string{service.ApplicationsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(application.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// ServiceCreateBulk is the builder for creating many Service entities in bulk.
type ServiceCreateBulk struct {
	config
	err      error
	builders []*ServiceCreate
}

// Save creates the Service entities in the database.
func (scb *ServiceCreateBulk) Save(ctx context.Context) ([]*Service, error) {
	if scb.err != nil {
		return nil, scb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(scb.builders))
	nodes := make([]*Service, len(scb.builders))
	mutators := make([]Mutator, len(scb.builders))
	for i := range scb.builders {
		func(i int, root context.Context) {
			builder := scb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*ServiceMutation)
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
					_, err = mutators[i+1].Mutate(root, scb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, scb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, scb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (scb *ServiceCreateBulk) SaveX(ctx context.Context) []*Service {
	v, err := scb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (scb *ServiceCreateBulk) Exec(ctx context.Context) error {
	_, err := scb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (scb *ServiceCreateBulk) ExecX(ctx context.Context) {
	if err := scb.Exec(ctx); err != nil {
		panic(err)
	}
}
