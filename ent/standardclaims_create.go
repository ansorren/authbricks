// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/standardclaims"
	"go.authbricks.com/bricks/ent/user"
)

// StandardClaimsCreate is the builder for creating a StandardClaims entity.
type StandardClaimsCreate struct {
	config
	mutation *StandardClaimsMutation
	hooks    []Hook
}

// SetSubject sets the "subject" field.
func (scc *StandardClaimsCreate) SetSubject(s string) *StandardClaimsCreate {
	scc.mutation.SetSubject(s)
	return scc
}

// SetName sets the "name" field.
func (scc *StandardClaimsCreate) SetName(s string) *StandardClaimsCreate {
	scc.mutation.SetName(s)
	return scc
}

// SetNillableName sets the "name" field if the given value is not nil.
func (scc *StandardClaimsCreate) SetNillableName(s *string) *StandardClaimsCreate {
	if s != nil {
		scc.SetName(*s)
	}
	return scc
}

// SetGivenName sets the "given_name" field.
func (scc *StandardClaimsCreate) SetGivenName(s string) *StandardClaimsCreate {
	scc.mutation.SetGivenName(s)
	return scc
}

// SetNillableGivenName sets the "given_name" field if the given value is not nil.
func (scc *StandardClaimsCreate) SetNillableGivenName(s *string) *StandardClaimsCreate {
	if s != nil {
		scc.SetGivenName(*s)
	}
	return scc
}

// SetFamilyName sets the "family_name" field.
func (scc *StandardClaimsCreate) SetFamilyName(s string) *StandardClaimsCreate {
	scc.mutation.SetFamilyName(s)
	return scc
}

// SetNillableFamilyName sets the "family_name" field if the given value is not nil.
func (scc *StandardClaimsCreate) SetNillableFamilyName(s *string) *StandardClaimsCreate {
	if s != nil {
		scc.SetFamilyName(*s)
	}
	return scc
}

// SetMiddleName sets the "middle_name" field.
func (scc *StandardClaimsCreate) SetMiddleName(s string) *StandardClaimsCreate {
	scc.mutation.SetMiddleName(s)
	return scc
}

// SetNillableMiddleName sets the "middle_name" field if the given value is not nil.
func (scc *StandardClaimsCreate) SetNillableMiddleName(s *string) *StandardClaimsCreate {
	if s != nil {
		scc.SetMiddleName(*s)
	}
	return scc
}

// SetNickname sets the "nickname" field.
func (scc *StandardClaimsCreate) SetNickname(s string) *StandardClaimsCreate {
	scc.mutation.SetNickname(s)
	return scc
}

// SetNillableNickname sets the "nickname" field if the given value is not nil.
func (scc *StandardClaimsCreate) SetNillableNickname(s *string) *StandardClaimsCreate {
	if s != nil {
		scc.SetNickname(*s)
	}
	return scc
}

// SetPreferredUsername sets the "preferred_username" field.
func (scc *StandardClaimsCreate) SetPreferredUsername(s string) *StandardClaimsCreate {
	scc.mutation.SetPreferredUsername(s)
	return scc
}

// SetNillablePreferredUsername sets the "preferred_username" field if the given value is not nil.
func (scc *StandardClaimsCreate) SetNillablePreferredUsername(s *string) *StandardClaimsCreate {
	if s != nil {
		scc.SetPreferredUsername(*s)
	}
	return scc
}

// SetProfile sets the "profile" field.
func (scc *StandardClaimsCreate) SetProfile(s string) *StandardClaimsCreate {
	scc.mutation.SetProfile(s)
	return scc
}

// SetNillableProfile sets the "profile" field if the given value is not nil.
func (scc *StandardClaimsCreate) SetNillableProfile(s *string) *StandardClaimsCreate {
	if s != nil {
		scc.SetProfile(*s)
	}
	return scc
}

// SetPicture sets the "picture" field.
func (scc *StandardClaimsCreate) SetPicture(s string) *StandardClaimsCreate {
	scc.mutation.SetPicture(s)
	return scc
}

// SetNillablePicture sets the "picture" field if the given value is not nil.
func (scc *StandardClaimsCreate) SetNillablePicture(s *string) *StandardClaimsCreate {
	if s != nil {
		scc.SetPicture(*s)
	}
	return scc
}

// SetWebsite sets the "website" field.
func (scc *StandardClaimsCreate) SetWebsite(s string) *StandardClaimsCreate {
	scc.mutation.SetWebsite(s)
	return scc
}

// SetNillableWebsite sets the "website" field if the given value is not nil.
func (scc *StandardClaimsCreate) SetNillableWebsite(s *string) *StandardClaimsCreate {
	if s != nil {
		scc.SetWebsite(*s)
	}
	return scc
}

// SetEmail sets the "email" field.
func (scc *StandardClaimsCreate) SetEmail(s string) *StandardClaimsCreate {
	scc.mutation.SetEmail(s)
	return scc
}

// SetNillableEmail sets the "email" field if the given value is not nil.
func (scc *StandardClaimsCreate) SetNillableEmail(s *string) *StandardClaimsCreate {
	if s != nil {
		scc.SetEmail(*s)
	}
	return scc
}

// SetEmailVerified sets the "email_verified" field.
func (scc *StandardClaimsCreate) SetEmailVerified(b bool) *StandardClaimsCreate {
	scc.mutation.SetEmailVerified(b)
	return scc
}

// SetNillableEmailVerified sets the "email_verified" field if the given value is not nil.
func (scc *StandardClaimsCreate) SetNillableEmailVerified(b *bool) *StandardClaimsCreate {
	if b != nil {
		scc.SetEmailVerified(*b)
	}
	return scc
}

// SetGender sets the "gender" field.
func (scc *StandardClaimsCreate) SetGender(s string) *StandardClaimsCreate {
	scc.mutation.SetGender(s)
	return scc
}

// SetNillableGender sets the "gender" field if the given value is not nil.
func (scc *StandardClaimsCreate) SetNillableGender(s *string) *StandardClaimsCreate {
	if s != nil {
		scc.SetGender(*s)
	}
	return scc
}

// SetBirthdate sets the "birthdate" field.
func (scc *StandardClaimsCreate) SetBirthdate(s string) *StandardClaimsCreate {
	scc.mutation.SetBirthdate(s)
	return scc
}

// SetNillableBirthdate sets the "birthdate" field if the given value is not nil.
func (scc *StandardClaimsCreate) SetNillableBirthdate(s *string) *StandardClaimsCreate {
	if s != nil {
		scc.SetBirthdate(*s)
	}
	return scc
}

// SetZoneinfo sets the "zoneinfo" field.
func (scc *StandardClaimsCreate) SetZoneinfo(s string) *StandardClaimsCreate {
	scc.mutation.SetZoneinfo(s)
	return scc
}

// SetNillableZoneinfo sets the "zoneinfo" field if the given value is not nil.
func (scc *StandardClaimsCreate) SetNillableZoneinfo(s *string) *StandardClaimsCreate {
	if s != nil {
		scc.SetZoneinfo(*s)
	}
	return scc
}

// SetLocale sets the "locale" field.
func (scc *StandardClaimsCreate) SetLocale(s string) *StandardClaimsCreate {
	scc.mutation.SetLocale(s)
	return scc
}

// SetNillableLocale sets the "locale" field if the given value is not nil.
func (scc *StandardClaimsCreate) SetNillableLocale(s *string) *StandardClaimsCreate {
	if s != nil {
		scc.SetLocale(*s)
	}
	return scc
}

// SetPhoneNumber sets the "phone_number" field.
func (scc *StandardClaimsCreate) SetPhoneNumber(s string) *StandardClaimsCreate {
	scc.mutation.SetPhoneNumber(s)
	return scc
}

// SetNillablePhoneNumber sets the "phone_number" field if the given value is not nil.
func (scc *StandardClaimsCreate) SetNillablePhoneNumber(s *string) *StandardClaimsCreate {
	if s != nil {
		scc.SetPhoneNumber(*s)
	}
	return scc
}

// SetPhoneNumberVerified sets the "phone_number_verified" field.
func (scc *StandardClaimsCreate) SetPhoneNumberVerified(b bool) *StandardClaimsCreate {
	scc.mutation.SetPhoneNumberVerified(b)
	return scc
}

// SetNillablePhoneNumberVerified sets the "phone_number_verified" field if the given value is not nil.
func (scc *StandardClaimsCreate) SetNillablePhoneNumberVerified(b *bool) *StandardClaimsCreate {
	if b != nil {
		scc.SetPhoneNumberVerified(*b)
	}
	return scc
}

// SetAddress sets the "address" field.
func (scc *StandardClaimsCreate) SetAddress(s string) *StandardClaimsCreate {
	scc.mutation.SetAddress(s)
	return scc
}

// SetNillableAddress sets the "address" field if the given value is not nil.
func (scc *StandardClaimsCreate) SetNillableAddress(s *string) *StandardClaimsCreate {
	if s != nil {
		scc.SetAddress(*s)
	}
	return scc
}

// SetUpdatedAt sets the "updated_at" field.
func (scc *StandardClaimsCreate) SetUpdatedAt(i int64) *StandardClaimsCreate {
	scc.mutation.SetUpdatedAt(i)
	return scc
}

// SetNillableUpdatedAt sets the "updated_at" field if the given value is not nil.
func (scc *StandardClaimsCreate) SetNillableUpdatedAt(i *int64) *StandardClaimsCreate {
	if i != nil {
		scc.SetUpdatedAt(*i)
	}
	return scc
}

// SetUserID sets the "user" edge to the User entity by ID.
func (scc *StandardClaimsCreate) SetUserID(id string) *StandardClaimsCreate {
	scc.mutation.SetUserID(id)
	return scc
}

// SetUser sets the "user" edge to the User entity.
func (scc *StandardClaimsCreate) SetUser(u *User) *StandardClaimsCreate {
	return scc.SetUserID(u.ID)
}

// Mutation returns the StandardClaimsMutation object of the builder.
func (scc *StandardClaimsCreate) Mutation() *StandardClaimsMutation {
	return scc.mutation
}

// Save creates the StandardClaims in the database.
func (scc *StandardClaimsCreate) Save(ctx context.Context) (*StandardClaims, error) {
	scc.defaults()
	return withHooks(ctx, scc.sqlSave, scc.mutation, scc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (scc *StandardClaimsCreate) SaveX(ctx context.Context) *StandardClaims {
	v, err := scc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (scc *StandardClaimsCreate) Exec(ctx context.Context) error {
	_, err := scc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (scc *StandardClaimsCreate) ExecX(ctx context.Context) {
	if err := scc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (scc *StandardClaimsCreate) defaults() {
	if _, ok := scc.mutation.EmailVerified(); !ok {
		v := standardclaims.DefaultEmailVerified
		scc.mutation.SetEmailVerified(v)
	}
	if _, ok := scc.mutation.PhoneNumberVerified(); !ok {
		v := standardclaims.DefaultPhoneNumberVerified
		scc.mutation.SetPhoneNumberVerified(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (scc *StandardClaimsCreate) check() error {
	if _, ok := scc.mutation.Subject(); !ok {
		return &ValidationError{Name: "subject", err: errors.New(`ent: missing required field "StandardClaims.subject"`)}
	}
	if v, ok := scc.mutation.Subject(); ok {
		if err := standardclaims.SubjectValidator(v); err != nil {
			return &ValidationError{Name: "subject", err: fmt.Errorf(`ent: validator failed for field "StandardClaims.subject": %w`, err)}
		}
	}
	if _, ok := scc.mutation.UserID(); !ok {
		return &ValidationError{Name: "user", err: errors.New(`ent: missing required edge "StandardClaims.user"`)}
	}
	return nil
}

func (scc *StandardClaimsCreate) sqlSave(ctx context.Context) (*StandardClaims, error) {
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
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	scc.mutation.id = &_node.ID
	scc.mutation.done = true
	return _node, nil
}

func (scc *StandardClaimsCreate) createSpec() (*StandardClaims, *sqlgraph.CreateSpec) {
	var (
		_node = &StandardClaims{config: scc.config}
		_spec = sqlgraph.NewCreateSpec(standardclaims.Table, sqlgraph.NewFieldSpec(standardclaims.FieldID, field.TypeInt))
	)
	if value, ok := scc.mutation.Subject(); ok {
		_spec.SetField(standardclaims.FieldSubject, field.TypeString, value)
		_node.Subject = value
	}
	if value, ok := scc.mutation.Name(); ok {
		_spec.SetField(standardclaims.FieldName, field.TypeString, value)
		_node.Name = value
	}
	if value, ok := scc.mutation.GivenName(); ok {
		_spec.SetField(standardclaims.FieldGivenName, field.TypeString, value)
		_node.GivenName = value
	}
	if value, ok := scc.mutation.FamilyName(); ok {
		_spec.SetField(standardclaims.FieldFamilyName, field.TypeString, value)
		_node.FamilyName = value
	}
	if value, ok := scc.mutation.MiddleName(); ok {
		_spec.SetField(standardclaims.FieldMiddleName, field.TypeString, value)
		_node.MiddleName = value
	}
	if value, ok := scc.mutation.Nickname(); ok {
		_spec.SetField(standardclaims.FieldNickname, field.TypeString, value)
		_node.Nickname = value
	}
	if value, ok := scc.mutation.PreferredUsername(); ok {
		_spec.SetField(standardclaims.FieldPreferredUsername, field.TypeString, value)
		_node.PreferredUsername = value
	}
	if value, ok := scc.mutation.Profile(); ok {
		_spec.SetField(standardclaims.FieldProfile, field.TypeString, value)
		_node.Profile = value
	}
	if value, ok := scc.mutation.Picture(); ok {
		_spec.SetField(standardclaims.FieldPicture, field.TypeString, value)
		_node.Picture = value
	}
	if value, ok := scc.mutation.Website(); ok {
		_spec.SetField(standardclaims.FieldWebsite, field.TypeString, value)
		_node.Website = value
	}
	if value, ok := scc.mutation.Email(); ok {
		_spec.SetField(standardclaims.FieldEmail, field.TypeString, value)
		_node.Email = value
	}
	if value, ok := scc.mutation.EmailVerified(); ok {
		_spec.SetField(standardclaims.FieldEmailVerified, field.TypeBool, value)
		_node.EmailVerified = value
	}
	if value, ok := scc.mutation.Gender(); ok {
		_spec.SetField(standardclaims.FieldGender, field.TypeString, value)
		_node.Gender = value
	}
	if value, ok := scc.mutation.Birthdate(); ok {
		_spec.SetField(standardclaims.FieldBirthdate, field.TypeString, value)
		_node.Birthdate = value
	}
	if value, ok := scc.mutation.Zoneinfo(); ok {
		_spec.SetField(standardclaims.FieldZoneinfo, field.TypeString, value)
		_node.Zoneinfo = value
	}
	if value, ok := scc.mutation.Locale(); ok {
		_spec.SetField(standardclaims.FieldLocale, field.TypeString, value)
		_node.Locale = value
	}
	if value, ok := scc.mutation.PhoneNumber(); ok {
		_spec.SetField(standardclaims.FieldPhoneNumber, field.TypeString, value)
		_node.PhoneNumber = value
	}
	if value, ok := scc.mutation.PhoneNumberVerified(); ok {
		_spec.SetField(standardclaims.FieldPhoneNumberVerified, field.TypeBool, value)
		_node.PhoneNumberVerified = value
	}
	if value, ok := scc.mutation.Address(); ok {
		_spec.SetField(standardclaims.FieldAddress, field.TypeString, value)
		_node.Address = value
	}
	if value, ok := scc.mutation.UpdatedAt(); ok {
		_spec.SetField(standardclaims.FieldUpdatedAt, field.TypeInt64, value)
		_node.UpdatedAt = value
	}
	if nodes := scc.mutation.UserIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   standardclaims.UserTable,
			Columns: []string{standardclaims.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.user_standard_claims = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// StandardClaimsCreateBulk is the builder for creating many StandardClaims entities in bulk.
type StandardClaimsCreateBulk struct {
	config
	err      error
	builders []*StandardClaimsCreate
}

// Save creates the StandardClaims entities in the database.
func (sccb *StandardClaimsCreateBulk) Save(ctx context.Context) ([]*StandardClaims, error) {
	if sccb.err != nil {
		return nil, sccb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(sccb.builders))
	nodes := make([]*StandardClaims, len(sccb.builders))
	mutators := make([]Mutator, len(sccb.builders))
	for i := range sccb.builders {
		func(i int, root context.Context) {
			builder := sccb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*StandardClaimsMutation)
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
				if specs[i].ID.Value != nil {
					id := specs[i].ID.Value.(int64)
					nodes[i].ID = int(id)
				}
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
func (sccb *StandardClaimsCreateBulk) SaveX(ctx context.Context) []*StandardClaims {
	v, err := sccb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (sccb *StandardClaimsCreateBulk) Exec(ctx context.Context) error {
	_, err := sccb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (sccb *StandardClaimsCreateBulk) ExecX(ctx context.Context) {
	if err := sccb.Exec(ctx); err != nil {
		panic(err)
	}
}
