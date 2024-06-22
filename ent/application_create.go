// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/application"
	"go.authbricks.com/bricks/ent/credentials"
	"go.authbricks.com/bricks/ent/service"
)

// ApplicationCreate is the builder for creating a Application entity.
type ApplicationCreate struct {
	config
	mutation *ApplicationMutation
	hooks    []Hook
}

// SetName sets the "name" field.
func (ac *ApplicationCreate) SetName(s string) *ApplicationCreate {
	ac.mutation.SetName(s)
	return ac
}

// SetPublic sets the "public" field.
func (ac *ApplicationCreate) SetPublic(b bool) *ApplicationCreate {
	ac.mutation.SetPublic(b)
	return ac
}

// SetNillablePublic sets the "public" field if the given value is not nil.
func (ac *ApplicationCreate) SetNillablePublic(b *bool) *ApplicationCreate {
	if b != nil {
		ac.SetPublic(*b)
	}
	return ac
}

// SetDescription sets the "description" field.
func (ac *ApplicationCreate) SetDescription(s string) *ApplicationCreate {
	ac.mutation.SetDescription(s)
	return ac
}

// SetRedirectUris sets the "redirect_uris" field.
func (ac *ApplicationCreate) SetRedirectUris(s []string) *ApplicationCreate {
	ac.mutation.SetRedirectUris(s)
	return ac
}

// SetResponseTypes sets the "response_types" field.
func (ac *ApplicationCreate) SetResponseTypes(s []string) *ApplicationCreate {
	ac.mutation.SetResponseTypes(s)
	return ac
}

// SetGrantTypes sets the "grant_types" field.
func (ac *ApplicationCreate) SetGrantTypes(s []string) *ApplicationCreate {
	ac.mutation.SetGrantTypes(s)
	return ac
}

// SetScopes sets the "scopes" field.
func (ac *ApplicationCreate) SetScopes(s []string) *ApplicationCreate {
	ac.mutation.SetScopes(s)
	return ac
}

// SetPkceRequired sets the "pkce_required" field.
func (ac *ApplicationCreate) SetPkceRequired(b bool) *ApplicationCreate {
	ac.mutation.SetPkceRequired(b)
	return ac
}

// SetNillablePkceRequired sets the "pkce_required" field if the given value is not nil.
func (ac *ApplicationCreate) SetNillablePkceRequired(b *bool) *ApplicationCreate {
	if b != nil {
		ac.SetPkceRequired(*b)
	}
	return ac
}

// SetS256CodeChallengeMethodRequired sets the "s256_code_challenge_method_required" field.
func (ac *ApplicationCreate) SetS256CodeChallengeMethodRequired(b bool) *ApplicationCreate {
	ac.mutation.SetS256CodeChallengeMethodRequired(b)
	return ac
}

// SetNillableS256CodeChallengeMethodRequired sets the "s256_code_challenge_method_required" field if the given value is not nil.
func (ac *ApplicationCreate) SetNillableS256CodeChallengeMethodRequired(b *bool) *ApplicationCreate {
	if b != nil {
		ac.SetS256CodeChallengeMethodRequired(*b)
	}
	return ac
}

// SetAllowedAuthenticationMethods sets the "allowed_authentication_methods" field.
func (ac *ApplicationCreate) SetAllowedAuthenticationMethods(s []string) *ApplicationCreate {
	ac.mutation.SetAllowedAuthenticationMethods(s)
	return ac
}

// SetID sets the "id" field.
func (ac *ApplicationCreate) SetID(s string) *ApplicationCreate {
	ac.mutation.SetID(s)
	return ac
}

// AddCredentialIDs adds the "credentials" edge to the Credentials entity by IDs.
func (ac *ApplicationCreate) AddCredentialIDs(ids ...string) *ApplicationCreate {
	ac.mutation.AddCredentialIDs(ids...)
	return ac
}

// AddCredentials adds the "credentials" edges to the Credentials entity.
func (ac *ApplicationCreate) AddCredentials(c ...*Credentials) *ApplicationCreate {
	ids := make([]string, len(c))
	for i := range c {
		ids[i] = c[i].ID
	}
	return ac.AddCredentialIDs(ids...)
}

// SetServiceID sets the "service" edge to the Service entity by ID.
func (ac *ApplicationCreate) SetServiceID(id string) *ApplicationCreate {
	ac.mutation.SetServiceID(id)
	return ac
}

// SetNillableServiceID sets the "service" edge to the Service entity by ID if the given value is not nil.
func (ac *ApplicationCreate) SetNillableServiceID(id *string) *ApplicationCreate {
	if id != nil {
		ac = ac.SetServiceID(*id)
	}
	return ac
}

// SetService sets the "service" edge to the Service entity.
func (ac *ApplicationCreate) SetService(s *Service) *ApplicationCreate {
	return ac.SetServiceID(s.ID)
}

// Mutation returns the ApplicationMutation object of the builder.
func (ac *ApplicationCreate) Mutation() *ApplicationMutation {
	return ac.mutation
}

// Save creates the Application in the database.
func (ac *ApplicationCreate) Save(ctx context.Context) (*Application, error) {
	ac.defaults()
	return withHooks(ctx, ac.sqlSave, ac.mutation, ac.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (ac *ApplicationCreate) SaveX(ctx context.Context) *Application {
	v, err := ac.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (ac *ApplicationCreate) Exec(ctx context.Context) error {
	_, err := ac.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ac *ApplicationCreate) ExecX(ctx context.Context) {
	if err := ac.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (ac *ApplicationCreate) defaults() {
	if _, ok := ac.mutation.Public(); !ok {
		v := application.DefaultPublic
		ac.mutation.SetPublic(v)
	}
	if _, ok := ac.mutation.PkceRequired(); !ok {
		v := application.DefaultPkceRequired
		ac.mutation.SetPkceRequired(v)
	}
	if _, ok := ac.mutation.S256CodeChallengeMethodRequired(); !ok {
		v := application.DefaultS256CodeChallengeMethodRequired
		ac.mutation.SetS256CodeChallengeMethodRequired(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (ac *ApplicationCreate) check() error {
	if _, ok := ac.mutation.Name(); !ok {
		return &ValidationError{Name: "name", err: errors.New(`ent: missing required field "Application.name"`)}
	}
	if v, ok := ac.mutation.Name(); ok {
		if err := application.NameValidator(v); err != nil {
			return &ValidationError{Name: "name", err: fmt.Errorf(`ent: validator failed for field "Application.name": %w`, err)}
		}
	}
	if _, ok := ac.mutation.Public(); !ok {
		return &ValidationError{Name: "public", err: errors.New(`ent: missing required field "Application.public"`)}
	}
	if _, ok := ac.mutation.Description(); !ok {
		return &ValidationError{Name: "description", err: errors.New(`ent: missing required field "Application.description"`)}
	}
	if _, ok := ac.mutation.RedirectUris(); !ok {
		return &ValidationError{Name: "redirect_uris", err: errors.New(`ent: missing required field "Application.redirect_uris"`)}
	}
	if _, ok := ac.mutation.ResponseTypes(); !ok {
		return &ValidationError{Name: "response_types", err: errors.New(`ent: missing required field "Application.response_types"`)}
	}
	if _, ok := ac.mutation.GrantTypes(); !ok {
		return &ValidationError{Name: "grant_types", err: errors.New(`ent: missing required field "Application.grant_types"`)}
	}
	if _, ok := ac.mutation.Scopes(); !ok {
		return &ValidationError{Name: "scopes", err: errors.New(`ent: missing required field "Application.scopes"`)}
	}
	if _, ok := ac.mutation.PkceRequired(); !ok {
		return &ValidationError{Name: "pkce_required", err: errors.New(`ent: missing required field "Application.pkce_required"`)}
	}
	if _, ok := ac.mutation.S256CodeChallengeMethodRequired(); !ok {
		return &ValidationError{Name: "s256_code_challenge_method_required", err: errors.New(`ent: missing required field "Application.s256_code_challenge_method_required"`)}
	}
	if _, ok := ac.mutation.AllowedAuthenticationMethods(); !ok {
		return &ValidationError{Name: "allowed_authentication_methods", err: errors.New(`ent: missing required field "Application.allowed_authentication_methods"`)}
	}
	if v, ok := ac.mutation.ID(); ok {
		if err := application.IDValidator(v); err != nil {
			return &ValidationError{Name: "id", err: fmt.Errorf(`ent: validator failed for field "Application.id": %w`, err)}
		}
	}
	return nil
}

func (ac *ApplicationCreate) sqlSave(ctx context.Context) (*Application, error) {
	if err := ac.check(); err != nil {
		return nil, err
	}
	_node, _spec := ac.createSpec()
	if err := sqlgraph.CreateNode(ctx, ac.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(string); ok {
			_node.ID = id
		} else {
			return nil, fmt.Errorf("unexpected Application.ID type: %T", _spec.ID.Value)
		}
	}
	ac.mutation.id = &_node.ID
	ac.mutation.done = true
	return _node, nil
}

func (ac *ApplicationCreate) createSpec() (*Application, *sqlgraph.CreateSpec) {
	var (
		_node = &Application{config: ac.config}
		_spec = sqlgraph.NewCreateSpec(application.Table, sqlgraph.NewFieldSpec(application.FieldID, field.TypeString))
	)
	if id, ok := ac.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if value, ok := ac.mutation.Name(); ok {
		_spec.SetField(application.FieldName, field.TypeString, value)
		_node.Name = value
	}
	if value, ok := ac.mutation.Public(); ok {
		_spec.SetField(application.FieldPublic, field.TypeBool, value)
		_node.Public = value
	}
	if value, ok := ac.mutation.Description(); ok {
		_spec.SetField(application.FieldDescription, field.TypeString, value)
		_node.Description = value
	}
	if value, ok := ac.mutation.RedirectUris(); ok {
		_spec.SetField(application.FieldRedirectUris, field.TypeJSON, value)
		_node.RedirectUris = value
	}
	if value, ok := ac.mutation.ResponseTypes(); ok {
		_spec.SetField(application.FieldResponseTypes, field.TypeJSON, value)
		_node.ResponseTypes = value
	}
	if value, ok := ac.mutation.GrantTypes(); ok {
		_spec.SetField(application.FieldGrantTypes, field.TypeJSON, value)
		_node.GrantTypes = value
	}
	if value, ok := ac.mutation.Scopes(); ok {
		_spec.SetField(application.FieldScopes, field.TypeJSON, value)
		_node.Scopes = value
	}
	if value, ok := ac.mutation.PkceRequired(); ok {
		_spec.SetField(application.FieldPkceRequired, field.TypeBool, value)
		_node.PkceRequired = value
	}
	if value, ok := ac.mutation.S256CodeChallengeMethodRequired(); ok {
		_spec.SetField(application.FieldS256CodeChallengeMethodRequired, field.TypeBool, value)
		_node.S256CodeChallengeMethodRequired = value
	}
	if value, ok := ac.mutation.AllowedAuthenticationMethods(); ok {
		_spec.SetField(application.FieldAllowedAuthenticationMethods, field.TypeJSON, value)
		_node.AllowedAuthenticationMethods = value
	}
	if nodes := ac.mutation.CredentialsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   application.CredentialsTable,
			Columns: []string{application.CredentialsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(credentials.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ac.mutation.ServiceIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   application.ServiceTable,
			Columns: []string{application.ServiceColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(service.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.service_applications = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// ApplicationCreateBulk is the builder for creating many Application entities in bulk.
type ApplicationCreateBulk struct {
	config
	err      error
	builders []*ApplicationCreate
}

// Save creates the Application entities in the database.
func (acb *ApplicationCreateBulk) Save(ctx context.Context) ([]*Application, error) {
	if acb.err != nil {
		return nil, acb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(acb.builders))
	nodes := make([]*Application, len(acb.builders))
	mutators := make([]Mutator, len(acb.builders))
	for i := range acb.builders {
		func(i int, root context.Context) {
			builder := acb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*ApplicationMutation)
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
					_, err = mutators[i+1].Mutate(root, acb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, acb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, acb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (acb *ApplicationCreateBulk) SaveX(ctx context.Context) []*Application {
	v, err := acb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (acb *ApplicationCreateBulk) Exec(ctx context.Context) error {
	_, err := acb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (acb *ApplicationCreateBulk) ExecX(ctx context.Context) {
	if err := acb.Exec(ctx); err != nil {
		panic(err)
	}
}
