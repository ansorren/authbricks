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
	"go.authbricks.com/bricks/ent/application"
	"go.authbricks.com/bricks/ent/credentials"
	"go.authbricks.com/bricks/ent/predicate"
	"go.authbricks.com/bricks/ent/service"
)

// ApplicationUpdate is the builder for updating Application entities.
type ApplicationUpdate struct {
	config
	hooks    []Hook
	mutation *ApplicationMutation
}

// Where appends a list predicates to the ApplicationUpdate builder.
func (au *ApplicationUpdate) Where(ps ...predicate.Application) *ApplicationUpdate {
	au.mutation.Where(ps...)
	return au
}

// SetName sets the "name" field.
func (au *ApplicationUpdate) SetName(s string) *ApplicationUpdate {
	au.mutation.SetName(s)
	return au
}

// SetNillableName sets the "name" field if the given value is not nil.
func (au *ApplicationUpdate) SetNillableName(s *string) *ApplicationUpdate {
	if s != nil {
		au.SetName(*s)
	}
	return au
}

// SetPublic sets the "public" field.
func (au *ApplicationUpdate) SetPublic(b bool) *ApplicationUpdate {
	au.mutation.SetPublic(b)
	return au
}

// SetNillablePublic sets the "public" field if the given value is not nil.
func (au *ApplicationUpdate) SetNillablePublic(b *bool) *ApplicationUpdate {
	if b != nil {
		au.SetPublic(*b)
	}
	return au
}

// SetDescription sets the "description" field.
func (au *ApplicationUpdate) SetDescription(s string) *ApplicationUpdate {
	au.mutation.SetDescription(s)
	return au
}

// SetNillableDescription sets the "description" field if the given value is not nil.
func (au *ApplicationUpdate) SetNillableDescription(s *string) *ApplicationUpdate {
	if s != nil {
		au.SetDescription(*s)
	}
	return au
}

// SetRedirectUris sets the "redirect_uris" field.
func (au *ApplicationUpdate) SetRedirectUris(s []string) *ApplicationUpdate {
	au.mutation.SetRedirectUris(s)
	return au
}

// AppendRedirectUris appends s to the "redirect_uris" field.
func (au *ApplicationUpdate) AppendRedirectUris(s []string) *ApplicationUpdate {
	au.mutation.AppendRedirectUris(s)
	return au
}

// SetResponseTypes sets the "response_types" field.
func (au *ApplicationUpdate) SetResponseTypes(s []string) *ApplicationUpdate {
	au.mutation.SetResponseTypes(s)
	return au
}

// AppendResponseTypes appends s to the "response_types" field.
func (au *ApplicationUpdate) AppendResponseTypes(s []string) *ApplicationUpdate {
	au.mutation.AppendResponseTypes(s)
	return au
}

// SetGrantTypes sets the "grant_types" field.
func (au *ApplicationUpdate) SetGrantTypes(s []string) *ApplicationUpdate {
	au.mutation.SetGrantTypes(s)
	return au
}

// AppendGrantTypes appends s to the "grant_types" field.
func (au *ApplicationUpdate) AppendGrantTypes(s []string) *ApplicationUpdate {
	au.mutation.AppendGrantTypes(s)
	return au
}

// SetScopes sets the "scopes" field.
func (au *ApplicationUpdate) SetScopes(s []string) *ApplicationUpdate {
	au.mutation.SetScopes(s)
	return au
}

// AppendScopes appends s to the "scopes" field.
func (au *ApplicationUpdate) AppendScopes(s []string) *ApplicationUpdate {
	au.mutation.AppendScopes(s)
	return au
}

// SetPkceRequired sets the "pkce_required" field.
func (au *ApplicationUpdate) SetPkceRequired(b bool) *ApplicationUpdate {
	au.mutation.SetPkceRequired(b)
	return au
}

// SetNillablePkceRequired sets the "pkce_required" field if the given value is not nil.
func (au *ApplicationUpdate) SetNillablePkceRequired(b *bool) *ApplicationUpdate {
	if b != nil {
		au.SetPkceRequired(*b)
	}
	return au
}

// SetS256CodeChallengeMethodRequired sets the "s256_code_challenge_method_required" field.
func (au *ApplicationUpdate) SetS256CodeChallengeMethodRequired(b bool) *ApplicationUpdate {
	au.mutation.SetS256CodeChallengeMethodRequired(b)
	return au
}

// SetNillableS256CodeChallengeMethodRequired sets the "s256_code_challenge_method_required" field if the given value is not nil.
func (au *ApplicationUpdate) SetNillableS256CodeChallengeMethodRequired(b *bool) *ApplicationUpdate {
	if b != nil {
		au.SetS256CodeChallengeMethodRequired(*b)
	}
	return au
}

// SetAllowedAuthenticationMethods sets the "allowed_authentication_methods" field.
func (au *ApplicationUpdate) SetAllowedAuthenticationMethods(s []string) *ApplicationUpdate {
	au.mutation.SetAllowedAuthenticationMethods(s)
	return au
}

// AppendAllowedAuthenticationMethods appends s to the "allowed_authentication_methods" field.
func (au *ApplicationUpdate) AppendAllowedAuthenticationMethods(s []string) *ApplicationUpdate {
	au.mutation.AppendAllowedAuthenticationMethods(s)
	return au
}

// AddCredentialIDs adds the "credentials" edge to the Credentials entity by IDs.
func (au *ApplicationUpdate) AddCredentialIDs(ids ...string) *ApplicationUpdate {
	au.mutation.AddCredentialIDs(ids...)
	return au
}

// AddCredentials adds the "credentials" edges to the Credentials entity.
func (au *ApplicationUpdate) AddCredentials(c ...*Credentials) *ApplicationUpdate {
	ids := make([]string, len(c))
	for i := range c {
		ids[i] = c[i].ID
	}
	return au.AddCredentialIDs(ids...)
}

// SetServiceID sets the "service" edge to the Service entity by ID.
func (au *ApplicationUpdate) SetServiceID(id string) *ApplicationUpdate {
	au.mutation.SetServiceID(id)
	return au
}

// SetNillableServiceID sets the "service" edge to the Service entity by ID if the given value is not nil.
func (au *ApplicationUpdate) SetNillableServiceID(id *string) *ApplicationUpdate {
	if id != nil {
		au = au.SetServiceID(*id)
	}
	return au
}

// SetService sets the "service" edge to the Service entity.
func (au *ApplicationUpdate) SetService(s *Service) *ApplicationUpdate {
	return au.SetServiceID(s.ID)
}

// Mutation returns the ApplicationMutation object of the builder.
func (au *ApplicationUpdate) Mutation() *ApplicationMutation {
	return au.mutation
}

// ClearCredentials clears all "credentials" edges to the Credentials entity.
func (au *ApplicationUpdate) ClearCredentials() *ApplicationUpdate {
	au.mutation.ClearCredentials()
	return au
}

// RemoveCredentialIDs removes the "credentials" edge to Credentials entities by IDs.
func (au *ApplicationUpdate) RemoveCredentialIDs(ids ...string) *ApplicationUpdate {
	au.mutation.RemoveCredentialIDs(ids...)
	return au
}

// RemoveCredentials removes "credentials" edges to Credentials entities.
func (au *ApplicationUpdate) RemoveCredentials(c ...*Credentials) *ApplicationUpdate {
	ids := make([]string, len(c))
	for i := range c {
		ids[i] = c[i].ID
	}
	return au.RemoveCredentialIDs(ids...)
}

// ClearService clears the "service" edge to the Service entity.
func (au *ApplicationUpdate) ClearService() *ApplicationUpdate {
	au.mutation.ClearService()
	return au
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (au *ApplicationUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, au.sqlSave, au.mutation, au.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (au *ApplicationUpdate) SaveX(ctx context.Context) int {
	affected, err := au.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (au *ApplicationUpdate) Exec(ctx context.Context) error {
	_, err := au.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (au *ApplicationUpdate) ExecX(ctx context.Context) {
	if err := au.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (au *ApplicationUpdate) check() error {
	if v, ok := au.mutation.Name(); ok {
		if err := application.NameValidator(v); err != nil {
			return &ValidationError{Name: "name", err: fmt.Errorf(`ent: validator failed for field "Application.name": %w`, err)}
		}
	}
	return nil
}

func (au *ApplicationUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := au.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(application.Table, application.Columns, sqlgraph.NewFieldSpec(application.FieldID, field.TypeString))
	if ps := au.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := au.mutation.Name(); ok {
		_spec.SetField(application.FieldName, field.TypeString, value)
	}
	if value, ok := au.mutation.Public(); ok {
		_spec.SetField(application.FieldPublic, field.TypeBool, value)
	}
	if value, ok := au.mutation.Description(); ok {
		_spec.SetField(application.FieldDescription, field.TypeString, value)
	}
	if value, ok := au.mutation.RedirectUris(); ok {
		_spec.SetField(application.FieldRedirectUris, field.TypeJSON, value)
	}
	if value, ok := au.mutation.AppendedRedirectUris(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, application.FieldRedirectUris, value)
		})
	}
	if value, ok := au.mutation.ResponseTypes(); ok {
		_spec.SetField(application.FieldResponseTypes, field.TypeJSON, value)
	}
	if value, ok := au.mutation.AppendedResponseTypes(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, application.FieldResponseTypes, value)
		})
	}
	if value, ok := au.mutation.GrantTypes(); ok {
		_spec.SetField(application.FieldGrantTypes, field.TypeJSON, value)
	}
	if value, ok := au.mutation.AppendedGrantTypes(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, application.FieldGrantTypes, value)
		})
	}
	if value, ok := au.mutation.Scopes(); ok {
		_spec.SetField(application.FieldScopes, field.TypeJSON, value)
	}
	if value, ok := au.mutation.AppendedScopes(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, application.FieldScopes, value)
		})
	}
	if value, ok := au.mutation.PkceRequired(); ok {
		_spec.SetField(application.FieldPkceRequired, field.TypeBool, value)
	}
	if value, ok := au.mutation.S256CodeChallengeMethodRequired(); ok {
		_spec.SetField(application.FieldS256CodeChallengeMethodRequired, field.TypeBool, value)
	}
	if value, ok := au.mutation.AllowedAuthenticationMethods(); ok {
		_spec.SetField(application.FieldAllowedAuthenticationMethods, field.TypeJSON, value)
	}
	if value, ok := au.mutation.AppendedAllowedAuthenticationMethods(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, application.FieldAllowedAuthenticationMethods, value)
		})
	}
	if au.mutation.CredentialsCleared() {
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
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := au.mutation.RemovedCredentialsIDs(); len(nodes) > 0 && !au.mutation.CredentialsCleared() {
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
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := au.mutation.CredentialsIDs(); len(nodes) > 0 {
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
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if au.mutation.ServiceCleared() {
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
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := au.mutation.ServiceIDs(); len(nodes) > 0 {
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
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, au.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{application.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	au.mutation.done = true
	return n, nil
}

// ApplicationUpdateOne is the builder for updating a single Application entity.
type ApplicationUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *ApplicationMutation
}

// SetName sets the "name" field.
func (auo *ApplicationUpdateOne) SetName(s string) *ApplicationUpdateOne {
	auo.mutation.SetName(s)
	return auo
}

// SetNillableName sets the "name" field if the given value is not nil.
func (auo *ApplicationUpdateOne) SetNillableName(s *string) *ApplicationUpdateOne {
	if s != nil {
		auo.SetName(*s)
	}
	return auo
}

// SetPublic sets the "public" field.
func (auo *ApplicationUpdateOne) SetPublic(b bool) *ApplicationUpdateOne {
	auo.mutation.SetPublic(b)
	return auo
}

// SetNillablePublic sets the "public" field if the given value is not nil.
func (auo *ApplicationUpdateOne) SetNillablePublic(b *bool) *ApplicationUpdateOne {
	if b != nil {
		auo.SetPublic(*b)
	}
	return auo
}

// SetDescription sets the "description" field.
func (auo *ApplicationUpdateOne) SetDescription(s string) *ApplicationUpdateOne {
	auo.mutation.SetDescription(s)
	return auo
}

// SetNillableDescription sets the "description" field if the given value is not nil.
func (auo *ApplicationUpdateOne) SetNillableDescription(s *string) *ApplicationUpdateOne {
	if s != nil {
		auo.SetDescription(*s)
	}
	return auo
}

// SetRedirectUris sets the "redirect_uris" field.
func (auo *ApplicationUpdateOne) SetRedirectUris(s []string) *ApplicationUpdateOne {
	auo.mutation.SetRedirectUris(s)
	return auo
}

// AppendRedirectUris appends s to the "redirect_uris" field.
func (auo *ApplicationUpdateOne) AppendRedirectUris(s []string) *ApplicationUpdateOne {
	auo.mutation.AppendRedirectUris(s)
	return auo
}

// SetResponseTypes sets the "response_types" field.
func (auo *ApplicationUpdateOne) SetResponseTypes(s []string) *ApplicationUpdateOne {
	auo.mutation.SetResponseTypes(s)
	return auo
}

// AppendResponseTypes appends s to the "response_types" field.
func (auo *ApplicationUpdateOne) AppendResponseTypes(s []string) *ApplicationUpdateOne {
	auo.mutation.AppendResponseTypes(s)
	return auo
}

// SetGrantTypes sets the "grant_types" field.
func (auo *ApplicationUpdateOne) SetGrantTypes(s []string) *ApplicationUpdateOne {
	auo.mutation.SetGrantTypes(s)
	return auo
}

// AppendGrantTypes appends s to the "grant_types" field.
func (auo *ApplicationUpdateOne) AppendGrantTypes(s []string) *ApplicationUpdateOne {
	auo.mutation.AppendGrantTypes(s)
	return auo
}

// SetScopes sets the "scopes" field.
func (auo *ApplicationUpdateOne) SetScopes(s []string) *ApplicationUpdateOne {
	auo.mutation.SetScopes(s)
	return auo
}

// AppendScopes appends s to the "scopes" field.
func (auo *ApplicationUpdateOne) AppendScopes(s []string) *ApplicationUpdateOne {
	auo.mutation.AppendScopes(s)
	return auo
}

// SetPkceRequired sets the "pkce_required" field.
func (auo *ApplicationUpdateOne) SetPkceRequired(b bool) *ApplicationUpdateOne {
	auo.mutation.SetPkceRequired(b)
	return auo
}

// SetNillablePkceRequired sets the "pkce_required" field if the given value is not nil.
func (auo *ApplicationUpdateOne) SetNillablePkceRequired(b *bool) *ApplicationUpdateOne {
	if b != nil {
		auo.SetPkceRequired(*b)
	}
	return auo
}

// SetS256CodeChallengeMethodRequired sets the "s256_code_challenge_method_required" field.
func (auo *ApplicationUpdateOne) SetS256CodeChallengeMethodRequired(b bool) *ApplicationUpdateOne {
	auo.mutation.SetS256CodeChallengeMethodRequired(b)
	return auo
}

// SetNillableS256CodeChallengeMethodRequired sets the "s256_code_challenge_method_required" field if the given value is not nil.
func (auo *ApplicationUpdateOne) SetNillableS256CodeChallengeMethodRequired(b *bool) *ApplicationUpdateOne {
	if b != nil {
		auo.SetS256CodeChallengeMethodRequired(*b)
	}
	return auo
}

// SetAllowedAuthenticationMethods sets the "allowed_authentication_methods" field.
func (auo *ApplicationUpdateOne) SetAllowedAuthenticationMethods(s []string) *ApplicationUpdateOne {
	auo.mutation.SetAllowedAuthenticationMethods(s)
	return auo
}

// AppendAllowedAuthenticationMethods appends s to the "allowed_authentication_methods" field.
func (auo *ApplicationUpdateOne) AppendAllowedAuthenticationMethods(s []string) *ApplicationUpdateOne {
	auo.mutation.AppendAllowedAuthenticationMethods(s)
	return auo
}

// AddCredentialIDs adds the "credentials" edge to the Credentials entity by IDs.
func (auo *ApplicationUpdateOne) AddCredentialIDs(ids ...string) *ApplicationUpdateOne {
	auo.mutation.AddCredentialIDs(ids...)
	return auo
}

// AddCredentials adds the "credentials" edges to the Credentials entity.
func (auo *ApplicationUpdateOne) AddCredentials(c ...*Credentials) *ApplicationUpdateOne {
	ids := make([]string, len(c))
	for i := range c {
		ids[i] = c[i].ID
	}
	return auo.AddCredentialIDs(ids...)
}

// SetServiceID sets the "service" edge to the Service entity by ID.
func (auo *ApplicationUpdateOne) SetServiceID(id string) *ApplicationUpdateOne {
	auo.mutation.SetServiceID(id)
	return auo
}

// SetNillableServiceID sets the "service" edge to the Service entity by ID if the given value is not nil.
func (auo *ApplicationUpdateOne) SetNillableServiceID(id *string) *ApplicationUpdateOne {
	if id != nil {
		auo = auo.SetServiceID(*id)
	}
	return auo
}

// SetService sets the "service" edge to the Service entity.
func (auo *ApplicationUpdateOne) SetService(s *Service) *ApplicationUpdateOne {
	return auo.SetServiceID(s.ID)
}

// Mutation returns the ApplicationMutation object of the builder.
func (auo *ApplicationUpdateOne) Mutation() *ApplicationMutation {
	return auo.mutation
}

// ClearCredentials clears all "credentials" edges to the Credentials entity.
func (auo *ApplicationUpdateOne) ClearCredentials() *ApplicationUpdateOne {
	auo.mutation.ClearCredentials()
	return auo
}

// RemoveCredentialIDs removes the "credentials" edge to Credentials entities by IDs.
func (auo *ApplicationUpdateOne) RemoveCredentialIDs(ids ...string) *ApplicationUpdateOne {
	auo.mutation.RemoveCredentialIDs(ids...)
	return auo
}

// RemoveCredentials removes "credentials" edges to Credentials entities.
func (auo *ApplicationUpdateOne) RemoveCredentials(c ...*Credentials) *ApplicationUpdateOne {
	ids := make([]string, len(c))
	for i := range c {
		ids[i] = c[i].ID
	}
	return auo.RemoveCredentialIDs(ids...)
}

// ClearService clears the "service" edge to the Service entity.
func (auo *ApplicationUpdateOne) ClearService() *ApplicationUpdateOne {
	auo.mutation.ClearService()
	return auo
}

// Where appends a list predicates to the ApplicationUpdate builder.
func (auo *ApplicationUpdateOne) Where(ps ...predicate.Application) *ApplicationUpdateOne {
	auo.mutation.Where(ps...)
	return auo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (auo *ApplicationUpdateOne) Select(field string, fields ...string) *ApplicationUpdateOne {
	auo.fields = append([]string{field}, fields...)
	return auo
}

// Save executes the query and returns the updated Application entity.
func (auo *ApplicationUpdateOne) Save(ctx context.Context) (*Application, error) {
	return withHooks(ctx, auo.sqlSave, auo.mutation, auo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (auo *ApplicationUpdateOne) SaveX(ctx context.Context) *Application {
	node, err := auo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (auo *ApplicationUpdateOne) Exec(ctx context.Context) error {
	_, err := auo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (auo *ApplicationUpdateOne) ExecX(ctx context.Context) {
	if err := auo.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (auo *ApplicationUpdateOne) check() error {
	if v, ok := auo.mutation.Name(); ok {
		if err := application.NameValidator(v); err != nil {
			return &ValidationError{Name: "name", err: fmt.Errorf(`ent: validator failed for field "Application.name": %w`, err)}
		}
	}
	return nil
}

func (auo *ApplicationUpdateOne) sqlSave(ctx context.Context) (_node *Application, err error) {
	if err := auo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(application.Table, application.Columns, sqlgraph.NewFieldSpec(application.FieldID, field.TypeString))
	id, ok := auo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "Application.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := auo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, application.FieldID)
		for _, f := range fields {
			if !application.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != application.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := auo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := auo.mutation.Name(); ok {
		_spec.SetField(application.FieldName, field.TypeString, value)
	}
	if value, ok := auo.mutation.Public(); ok {
		_spec.SetField(application.FieldPublic, field.TypeBool, value)
	}
	if value, ok := auo.mutation.Description(); ok {
		_spec.SetField(application.FieldDescription, field.TypeString, value)
	}
	if value, ok := auo.mutation.RedirectUris(); ok {
		_spec.SetField(application.FieldRedirectUris, field.TypeJSON, value)
	}
	if value, ok := auo.mutation.AppendedRedirectUris(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, application.FieldRedirectUris, value)
		})
	}
	if value, ok := auo.mutation.ResponseTypes(); ok {
		_spec.SetField(application.FieldResponseTypes, field.TypeJSON, value)
	}
	if value, ok := auo.mutation.AppendedResponseTypes(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, application.FieldResponseTypes, value)
		})
	}
	if value, ok := auo.mutation.GrantTypes(); ok {
		_spec.SetField(application.FieldGrantTypes, field.TypeJSON, value)
	}
	if value, ok := auo.mutation.AppendedGrantTypes(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, application.FieldGrantTypes, value)
		})
	}
	if value, ok := auo.mutation.Scopes(); ok {
		_spec.SetField(application.FieldScopes, field.TypeJSON, value)
	}
	if value, ok := auo.mutation.AppendedScopes(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, application.FieldScopes, value)
		})
	}
	if value, ok := auo.mutation.PkceRequired(); ok {
		_spec.SetField(application.FieldPkceRequired, field.TypeBool, value)
	}
	if value, ok := auo.mutation.S256CodeChallengeMethodRequired(); ok {
		_spec.SetField(application.FieldS256CodeChallengeMethodRequired, field.TypeBool, value)
	}
	if value, ok := auo.mutation.AllowedAuthenticationMethods(); ok {
		_spec.SetField(application.FieldAllowedAuthenticationMethods, field.TypeJSON, value)
	}
	if value, ok := auo.mutation.AppendedAllowedAuthenticationMethods(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, application.FieldAllowedAuthenticationMethods, value)
		})
	}
	if auo.mutation.CredentialsCleared() {
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
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := auo.mutation.RemovedCredentialsIDs(); len(nodes) > 0 && !auo.mutation.CredentialsCleared() {
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
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := auo.mutation.CredentialsIDs(); len(nodes) > 0 {
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
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if auo.mutation.ServiceCleared() {
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
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := auo.mutation.ServiceIDs(); len(nodes) > 0 {
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
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &Application{config: auo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, auo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{application.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	auo.mutation.done = true
	return _node, nil
}
