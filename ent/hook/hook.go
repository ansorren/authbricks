// Code generated by ent, DO NOT EDIT.

package hook

import (
	"context"
	"fmt"

	"go.authbricks.com/bricks/ent"
)

// The ApplicationFunc type is an adapter to allow the use of ordinary
// function as Application mutator.
type ApplicationFunc func(context.Context, *ent.ApplicationMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f ApplicationFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.ApplicationMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.ApplicationMutation", m)
}

// The AuthorizationCodeFunc type is an adapter to allow the use of ordinary
// function as AuthorizationCode mutator.
type AuthorizationCodeFunc func(context.Context, *ent.AuthorizationCodeMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f AuthorizationCodeFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.AuthorizationCodeMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.AuthorizationCodeMutation", m)
}

// The AuthorizationEndpointConfigFunc type is an adapter to allow the use of ordinary
// function as AuthorizationEndpointConfig mutator.
type AuthorizationEndpointConfigFunc func(context.Context, *ent.AuthorizationEndpointConfigMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f AuthorizationEndpointConfigFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.AuthorizationEndpointConfigMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.AuthorizationEndpointConfigMutation", m)
}

// The AuthorizationPayloadFunc type is an adapter to allow the use of ordinary
// function as AuthorizationPayload mutator.
type AuthorizationPayloadFunc func(context.Context, *ent.AuthorizationPayloadMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f AuthorizationPayloadFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.AuthorizationPayloadMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.AuthorizationPayloadMutation", m)
}

// The CookieStoreFunc type is an adapter to allow the use of ordinary
// function as CookieStore mutator.
type CookieStoreFunc func(context.Context, *ent.CookieStoreMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f CookieStoreFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.CookieStoreMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.CookieStoreMutation", m)
}

// The CredentialsFunc type is an adapter to allow the use of ordinary
// function as Credentials mutator.
type CredentialsFunc func(context.Context, *ent.CredentialsMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f CredentialsFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.CredentialsMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.CredentialsMutation", m)
}

// The IntrospectionEndpointConfigFunc type is an adapter to allow the use of ordinary
// function as IntrospectionEndpointConfig mutator.
type IntrospectionEndpointConfigFunc func(context.Context, *ent.IntrospectionEndpointConfigMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f IntrospectionEndpointConfigFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.IntrospectionEndpointConfigMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.IntrospectionEndpointConfigMutation", m)
}

// The JwksEndpointConfigFunc type is an adapter to allow the use of ordinary
// function as JwksEndpointConfig mutator.
type JwksEndpointConfigFunc func(context.Context, *ent.JwksEndpointConfigMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f JwksEndpointConfigFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.JwksEndpointConfigMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.JwksEndpointConfigMutation", m)
}

// The KeySetFunc type is an adapter to allow the use of ordinary
// function as KeySet mutator.
type KeySetFunc func(context.Context, *ent.KeySetMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f KeySetFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.KeySetMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.KeySetMutation", m)
}

// The RefreshTokenFunc type is an adapter to allow the use of ordinary
// function as RefreshToken mutator.
type RefreshTokenFunc func(context.Context, *ent.RefreshTokenMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f RefreshTokenFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.RefreshTokenMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.RefreshTokenMutation", m)
}

// The ServiceFunc type is an adapter to allow the use of ordinary
// function as Service mutator.
type ServiceFunc func(context.Context, *ent.ServiceMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f ServiceFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.ServiceMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.ServiceMutation", m)
}

// The SessionFunc type is an adapter to allow the use of ordinary
// function as Session mutator.
type SessionFunc func(context.Context, *ent.SessionMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f SessionFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.SessionMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.SessionMutation", m)
}

// The SigningKeyFunc type is an adapter to allow the use of ordinary
// function as SigningKey mutator.
type SigningKeyFunc func(context.Context, *ent.SigningKeyMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f SigningKeyFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.SigningKeyMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.SigningKeyMutation", m)
}

// The StandardClaimsFunc type is an adapter to allow the use of ordinary
// function as StandardClaims mutator.
type StandardClaimsFunc func(context.Context, *ent.StandardClaimsMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f StandardClaimsFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.StandardClaimsMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.StandardClaimsMutation", m)
}

// The TokenEndpointConfigFunc type is an adapter to allow the use of ordinary
// function as TokenEndpointConfig mutator.
type TokenEndpointConfigFunc func(context.Context, *ent.TokenEndpointConfigMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f TokenEndpointConfigFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.TokenEndpointConfigMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.TokenEndpointConfigMutation", m)
}

// The UserFunc type is an adapter to allow the use of ordinary
// function as User mutator.
type UserFunc func(context.Context, *ent.UserMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f UserFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.UserMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.UserMutation", m)
}

// The UserInfoEndpointConfigFunc type is an adapter to allow the use of ordinary
// function as UserInfoEndpointConfig mutator.
type UserInfoEndpointConfigFunc func(context.Context, *ent.UserInfoEndpointConfigMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f UserInfoEndpointConfigFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.UserInfoEndpointConfigMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.UserInfoEndpointConfigMutation", m)
}

// The UserPoolFunc type is an adapter to allow the use of ordinary
// function as UserPool mutator.
type UserPoolFunc func(context.Context, *ent.UserPoolMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f UserPoolFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.UserPoolMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.UserPoolMutation", m)
}

// The WellKnownEndpointConfigFunc type is an adapter to allow the use of ordinary
// function as WellKnownEndpointConfig mutator.
type WellKnownEndpointConfigFunc func(context.Context, *ent.WellKnownEndpointConfigMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f WellKnownEndpointConfigFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.WellKnownEndpointConfigMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.WellKnownEndpointConfigMutation", m)
}

// Condition is a hook condition function.
type Condition func(context.Context, ent.Mutation) bool

// And groups conditions with the AND operator.
func And(first, second Condition, rest ...Condition) Condition {
	return func(ctx context.Context, m ent.Mutation) bool {
		if !first(ctx, m) || !second(ctx, m) {
			return false
		}
		for _, cond := range rest {
			if !cond(ctx, m) {
				return false
			}
		}
		return true
	}
}

// Or groups conditions with the OR operator.
func Or(first, second Condition, rest ...Condition) Condition {
	return func(ctx context.Context, m ent.Mutation) bool {
		if first(ctx, m) || second(ctx, m) {
			return true
		}
		for _, cond := range rest {
			if cond(ctx, m) {
				return true
			}
		}
		return false
	}
}

// Not negates a given condition.
func Not(cond Condition) Condition {
	return func(ctx context.Context, m ent.Mutation) bool {
		return !cond(ctx, m)
	}
}

// HasOp is a condition testing mutation operation.
func HasOp(op ent.Op) Condition {
	return func(_ context.Context, m ent.Mutation) bool {
		return m.Op().Is(op)
	}
}

// HasAddedFields is a condition validating `.AddedField` on fields.
func HasAddedFields(field string, fields ...string) Condition {
	return func(_ context.Context, m ent.Mutation) bool {
		if _, exists := m.AddedField(field); !exists {
			return false
		}
		for _, field := range fields {
			if _, exists := m.AddedField(field); !exists {
				return false
			}
		}
		return true
	}
}

// HasClearedFields is a condition validating `.FieldCleared` on fields.
func HasClearedFields(field string, fields ...string) Condition {
	return func(_ context.Context, m ent.Mutation) bool {
		if exists := m.FieldCleared(field); !exists {
			return false
		}
		for _, field := range fields {
			if exists := m.FieldCleared(field); !exists {
				return false
			}
		}
		return true
	}
}

// HasFields is a condition validating `.Field` on fields.
func HasFields(field string, fields ...string) Condition {
	return func(_ context.Context, m ent.Mutation) bool {
		if _, exists := m.Field(field); !exists {
			return false
		}
		for _, field := range fields {
			if _, exists := m.Field(field); !exists {
				return false
			}
		}
		return true
	}
}

// If executes the given hook under condition.
//
//	hook.If(ComputeAverage, And(HasFields(...), HasAddedFields(...)))
func If(hk ent.Hook, cond Condition) ent.Hook {
	return func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			if cond(ctx, m) {
				return hk(next).Mutate(ctx, m)
			}
			return next.Mutate(ctx, m)
		})
	}
}

// On executes the given hook only for the given operation.
//
//	hook.On(Log, ent.Delete|ent.Create)
func On(hk ent.Hook, op ent.Op) ent.Hook {
	return If(hk, HasOp(op))
}

// Unless skips the given hook only for the given operation.
//
//	hook.Unless(Log, ent.Update|ent.UpdateOne)
func Unless(hk ent.Hook, op ent.Op) ent.Hook {
	return If(hk, Not(HasOp(op)))
}

// FixedError is a hook returning a fixed error.
func FixedError(err error) ent.Hook {
	return func(ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(context.Context, ent.Mutation) (ent.Value, error) {
			return nil, err
		})
	}
}

// Reject returns a hook that rejects all operations that match op.
//
//	func (T) Hooks() []ent.Hook {
//		return []ent.Hook{
//			Reject(ent.Delete|ent.Update),
//		}
//	}
func Reject(op ent.Op) ent.Hook {
	hk := FixedError(fmt.Errorf("%s operation is not allowed", op))
	return On(hk, op)
}

// Chain acts as a list of hooks and is effectively immutable.
// Once created, it will always hold the same set of hooks in the same order.
type Chain struct {
	hooks []ent.Hook
}

// NewChain creates a new chain of hooks.
func NewChain(hooks ...ent.Hook) Chain {
	return Chain{append([]ent.Hook(nil), hooks...)}
}

// Hook chains the list of hooks and returns the final hook.
func (c Chain) Hook() ent.Hook {
	return func(mutator ent.Mutator) ent.Mutator {
		for i := len(c.hooks) - 1; i >= 0; i-- {
			mutator = c.hooks[i](mutator)
		}
		return mutator
	}
}

// Append extends a chain, adding the specified hook
// as the last ones in the mutation flow.
func (c Chain) Append(hooks ...ent.Hook) Chain {
	newHooks := make([]ent.Hook, 0, len(c.hooks)+len(hooks))
	newHooks = append(newHooks, c.hooks...)
	newHooks = append(newHooks, hooks...)
	return Chain{newHooks}
}

// Extend extends a chain, adding the specified chain
// as the last ones in the mutation flow.
func (c Chain) Extend(chain Chain) Chain {
	return c.Append(chain.hooks...)
}
