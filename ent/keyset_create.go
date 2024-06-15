// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/keyset"
	"go.authbricks.com/bricks/ent/oauthserver"
	"go.authbricks.com/bricks/ent/signingkey"
)

// KeySetCreate is the builder for creating a KeySet entity.
type KeySetCreate struct {
	config
	mutation *KeySetMutation
	hooks    []Hook
}

// SetID sets the "id" field.
func (ksc *KeySetCreate) SetID(s string) *KeySetCreate {
	ksc.mutation.SetID(s)
	return ksc
}

// SetOauthServerID sets the "oauth_server" edge to the OAuthServer entity by ID.
func (ksc *KeySetCreate) SetOauthServerID(id int) *KeySetCreate {
	ksc.mutation.SetOauthServerID(id)
	return ksc
}

// SetNillableOauthServerID sets the "oauth_server" edge to the OAuthServer entity by ID if the given value is not nil.
func (ksc *KeySetCreate) SetNillableOauthServerID(id *int) *KeySetCreate {
	if id != nil {
		ksc = ksc.SetOauthServerID(*id)
	}
	return ksc
}

// SetOauthServer sets the "oauth_server" edge to the OAuthServer entity.
func (ksc *KeySetCreate) SetOauthServer(o *OAuthServer) *KeySetCreate {
	return ksc.SetOauthServerID(o.ID)
}

// AddSigningKeyIDs adds the "signing_keys" edge to the SigningKey entity by IDs.
func (ksc *KeySetCreate) AddSigningKeyIDs(ids ...string) *KeySetCreate {
	ksc.mutation.AddSigningKeyIDs(ids...)
	return ksc
}

// AddSigningKeys adds the "signing_keys" edges to the SigningKey entity.
func (ksc *KeySetCreate) AddSigningKeys(s ...*SigningKey) *KeySetCreate {
	ids := make([]string, len(s))
	for i := range s {
		ids[i] = s[i].ID
	}
	return ksc.AddSigningKeyIDs(ids...)
}

// Mutation returns the KeySetMutation object of the builder.
func (ksc *KeySetCreate) Mutation() *KeySetMutation {
	return ksc.mutation
}

// Save creates the KeySet in the database.
func (ksc *KeySetCreate) Save(ctx context.Context) (*KeySet, error) {
	return withHooks(ctx, ksc.sqlSave, ksc.mutation, ksc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (ksc *KeySetCreate) SaveX(ctx context.Context) *KeySet {
	v, err := ksc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (ksc *KeySetCreate) Exec(ctx context.Context) error {
	_, err := ksc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ksc *KeySetCreate) ExecX(ctx context.Context) {
	if err := ksc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (ksc *KeySetCreate) check() error {
	if v, ok := ksc.mutation.ID(); ok {
		if err := keyset.IDValidator(v); err != nil {
			return &ValidationError{Name: "id", err: fmt.Errorf(`ent: validator failed for field "KeySet.id": %w`, err)}
		}
	}
	return nil
}

func (ksc *KeySetCreate) sqlSave(ctx context.Context) (*KeySet, error) {
	if err := ksc.check(); err != nil {
		return nil, err
	}
	_node, _spec := ksc.createSpec()
	if err := sqlgraph.CreateNode(ctx, ksc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(string); ok {
			_node.ID = id
		} else {
			return nil, fmt.Errorf("unexpected KeySet.ID type: %T", _spec.ID.Value)
		}
	}
	ksc.mutation.id = &_node.ID
	ksc.mutation.done = true
	return _node, nil
}

func (ksc *KeySetCreate) createSpec() (*KeySet, *sqlgraph.CreateSpec) {
	var (
		_node = &KeySet{config: ksc.config}
		_spec = sqlgraph.NewCreateSpec(keyset.Table, sqlgraph.NewFieldSpec(keyset.FieldID, field.TypeString))
	)
	if id, ok := ksc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if nodes := ksc.mutation.OauthServerIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   keyset.OauthServerTable,
			Columns: []string{keyset.OauthServerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(oauthserver.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.oauth_server_key_set = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ksc.mutation.SigningKeysIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   keyset.SigningKeysTable,
			Columns: []string{keyset.SigningKeysColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(signingkey.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// KeySetCreateBulk is the builder for creating many KeySet entities in bulk.
type KeySetCreateBulk struct {
	config
	err      error
	builders []*KeySetCreate
}

// Save creates the KeySet entities in the database.
func (kscb *KeySetCreateBulk) Save(ctx context.Context) ([]*KeySet, error) {
	if kscb.err != nil {
		return nil, kscb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(kscb.builders))
	nodes := make([]*KeySet, len(kscb.builders))
	mutators := make([]Mutator, len(kscb.builders))
	for i := range kscb.builders {
		func(i int, root context.Context) {
			builder := kscb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*KeySetMutation)
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
					_, err = mutators[i+1].Mutate(root, kscb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, kscb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, kscb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (kscb *KeySetCreateBulk) SaveX(ctx context.Context) []*KeySet {
	v, err := kscb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (kscb *KeySetCreateBulk) Exec(ctx context.Context) error {
	_, err := kscb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (kscb *KeySetCreateBulk) ExecX(ctx context.Context) {
	if err := kscb.Exec(ctx); err != nil {
		panic(err)
	}
}
