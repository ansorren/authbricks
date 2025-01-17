// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/authorizationcode"
	"go.authbricks.com/bricks/ent/predicate"
)

// AuthorizationCodeQuery is the builder for querying AuthorizationCode entities.
type AuthorizationCodeQuery struct {
	config
	ctx        *QueryContext
	order      []authorizationcode.OrderOption
	inters     []Interceptor
	predicates []predicate.AuthorizationCode
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the AuthorizationCodeQuery builder.
func (acq *AuthorizationCodeQuery) Where(ps ...predicate.AuthorizationCode) *AuthorizationCodeQuery {
	acq.predicates = append(acq.predicates, ps...)
	return acq
}

// Limit the number of records to be returned by this query.
func (acq *AuthorizationCodeQuery) Limit(limit int) *AuthorizationCodeQuery {
	acq.ctx.Limit = &limit
	return acq
}

// Offset to start from.
func (acq *AuthorizationCodeQuery) Offset(offset int) *AuthorizationCodeQuery {
	acq.ctx.Offset = &offset
	return acq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (acq *AuthorizationCodeQuery) Unique(unique bool) *AuthorizationCodeQuery {
	acq.ctx.Unique = &unique
	return acq
}

// Order specifies how the records should be ordered.
func (acq *AuthorizationCodeQuery) Order(o ...authorizationcode.OrderOption) *AuthorizationCodeQuery {
	acq.order = append(acq.order, o...)
	return acq
}

// First returns the first AuthorizationCode entity from the query.
// Returns a *NotFoundError when no AuthorizationCode was found.
func (acq *AuthorizationCodeQuery) First(ctx context.Context) (*AuthorizationCode, error) {
	nodes, err := acq.Limit(1).All(setContextOp(ctx, acq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{authorizationcode.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (acq *AuthorizationCodeQuery) FirstX(ctx context.Context) *AuthorizationCode {
	node, err := acq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first AuthorizationCode ID from the query.
// Returns a *NotFoundError when no AuthorizationCode ID was found.
func (acq *AuthorizationCodeQuery) FirstID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = acq.Limit(1).IDs(setContextOp(ctx, acq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{authorizationcode.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (acq *AuthorizationCodeQuery) FirstIDX(ctx context.Context) string {
	id, err := acq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single AuthorizationCode entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one AuthorizationCode entity is found.
// Returns a *NotFoundError when no AuthorizationCode entities are found.
func (acq *AuthorizationCodeQuery) Only(ctx context.Context) (*AuthorizationCode, error) {
	nodes, err := acq.Limit(2).All(setContextOp(ctx, acq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{authorizationcode.Label}
	default:
		return nil, &NotSingularError{authorizationcode.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (acq *AuthorizationCodeQuery) OnlyX(ctx context.Context) *AuthorizationCode {
	node, err := acq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only AuthorizationCode ID in the query.
// Returns a *NotSingularError when more than one AuthorizationCode ID is found.
// Returns a *NotFoundError when no entities are found.
func (acq *AuthorizationCodeQuery) OnlyID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = acq.Limit(2).IDs(setContextOp(ctx, acq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{authorizationcode.Label}
	default:
		err = &NotSingularError{authorizationcode.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (acq *AuthorizationCodeQuery) OnlyIDX(ctx context.Context) string {
	id, err := acq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of AuthorizationCodes.
func (acq *AuthorizationCodeQuery) All(ctx context.Context) ([]*AuthorizationCode, error) {
	ctx = setContextOp(ctx, acq.ctx, "All")
	if err := acq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*AuthorizationCode, *AuthorizationCodeQuery]()
	return withInterceptors[[]*AuthorizationCode](ctx, acq, qr, acq.inters)
}

// AllX is like All, but panics if an error occurs.
func (acq *AuthorizationCodeQuery) AllX(ctx context.Context) []*AuthorizationCode {
	nodes, err := acq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of AuthorizationCode IDs.
func (acq *AuthorizationCodeQuery) IDs(ctx context.Context) (ids []string, err error) {
	if acq.ctx.Unique == nil && acq.path != nil {
		acq.Unique(true)
	}
	ctx = setContextOp(ctx, acq.ctx, "IDs")
	if err = acq.Select(authorizationcode.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (acq *AuthorizationCodeQuery) IDsX(ctx context.Context) []string {
	ids, err := acq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (acq *AuthorizationCodeQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, acq.ctx, "Count")
	if err := acq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, acq, querierCount[*AuthorizationCodeQuery](), acq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (acq *AuthorizationCodeQuery) CountX(ctx context.Context) int {
	count, err := acq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (acq *AuthorizationCodeQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, acq.ctx, "Exist")
	switch _, err := acq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (acq *AuthorizationCodeQuery) ExistX(ctx context.Context) bool {
	exist, err := acq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the AuthorizationCodeQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (acq *AuthorizationCodeQuery) Clone() *AuthorizationCodeQuery {
	if acq == nil {
		return nil
	}
	return &AuthorizationCodeQuery{
		config:     acq.config,
		ctx:        acq.ctx.Clone(),
		order:      append([]authorizationcode.OrderOption{}, acq.order...),
		inters:     append([]Interceptor{}, acq.inters...),
		predicates: append([]predicate.AuthorizationCode{}, acq.predicates...),
		// clone intermediate query.
		sql:  acq.sql.Clone(),
		path: acq.path,
	}
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		Application string `json:"application"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.AuthorizationCode.Query().
//		GroupBy(authorizationcode.FieldApplication).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (acq *AuthorizationCodeQuery) GroupBy(field string, fields ...string) *AuthorizationCodeGroupBy {
	acq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &AuthorizationCodeGroupBy{build: acq}
	grbuild.flds = &acq.ctx.Fields
	grbuild.label = authorizationcode.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		Application string `json:"application"`
//	}
//
//	client.AuthorizationCode.Query().
//		Select(authorizationcode.FieldApplication).
//		Scan(ctx, &v)
func (acq *AuthorizationCodeQuery) Select(fields ...string) *AuthorizationCodeSelect {
	acq.ctx.Fields = append(acq.ctx.Fields, fields...)
	sbuild := &AuthorizationCodeSelect{AuthorizationCodeQuery: acq}
	sbuild.label = authorizationcode.Label
	sbuild.flds, sbuild.scan = &acq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a AuthorizationCodeSelect configured with the given aggregations.
func (acq *AuthorizationCodeQuery) Aggregate(fns ...AggregateFunc) *AuthorizationCodeSelect {
	return acq.Select().Aggregate(fns...)
}

func (acq *AuthorizationCodeQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range acq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, acq); err != nil {
				return err
			}
		}
	}
	for _, f := range acq.ctx.Fields {
		if !authorizationcode.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if acq.path != nil {
		prev, err := acq.path(ctx)
		if err != nil {
			return err
		}
		acq.sql = prev
	}
	return nil
}

func (acq *AuthorizationCodeQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*AuthorizationCode, error) {
	var (
		nodes = []*AuthorizationCode{}
		_spec = acq.querySpec()
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*AuthorizationCode).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &AuthorizationCode{config: acq.config}
		nodes = append(nodes, node)
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, acq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	return nodes, nil
}

func (acq *AuthorizationCodeQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := acq.querySpec()
	_spec.Node.Columns = acq.ctx.Fields
	if len(acq.ctx.Fields) > 0 {
		_spec.Unique = acq.ctx.Unique != nil && *acq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, acq.driver, _spec)
}

func (acq *AuthorizationCodeQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(authorizationcode.Table, authorizationcode.Columns, sqlgraph.NewFieldSpec(authorizationcode.FieldID, field.TypeString))
	_spec.From = acq.sql
	if unique := acq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if acq.path != nil {
		_spec.Unique = true
	}
	if fields := acq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, authorizationcode.FieldID)
		for i := range fields {
			if fields[i] != authorizationcode.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := acq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := acq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := acq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := acq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (acq *AuthorizationCodeQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(acq.driver.Dialect())
	t1 := builder.Table(authorizationcode.Table)
	columns := acq.ctx.Fields
	if len(columns) == 0 {
		columns = authorizationcode.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if acq.sql != nil {
		selector = acq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if acq.ctx.Unique != nil && *acq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range acq.predicates {
		p(selector)
	}
	for _, p := range acq.order {
		p(selector)
	}
	if offset := acq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := acq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// AuthorizationCodeGroupBy is the group-by builder for AuthorizationCode entities.
type AuthorizationCodeGroupBy struct {
	selector
	build *AuthorizationCodeQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (acgb *AuthorizationCodeGroupBy) Aggregate(fns ...AggregateFunc) *AuthorizationCodeGroupBy {
	acgb.fns = append(acgb.fns, fns...)
	return acgb
}

// Scan applies the selector query and scans the result into the given value.
func (acgb *AuthorizationCodeGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, acgb.build.ctx, "GroupBy")
	if err := acgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*AuthorizationCodeQuery, *AuthorizationCodeGroupBy](ctx, acgb.build, acgb, acgb.build.inters, v)
}

func (acgb *AuthorizationCodeGroupBy) sqlScan(ctx context.Context, root *AuthorizationCodeQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(acgb.fns))
	for _, fn := range acgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*acgb.flds)+len(acgb.fns))
		for _, f := range *acgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*acgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := acgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// AuthorizationCodeSelect is the builder for selecting fields of AuthorizationCode entities.
type AuthorizationCodeSelect struct {
	*AuthorizationCodeQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (acs *AuthorizationCodeSelect) Aggregate(fns ...AggregateFunc) *AuthorizationCodeSelect {
	acs.fns = append(acs.fns, fns...)
	return acs
}

// Scan applies the selector query and scans the result into the given value.
func (acs *AuthorizationCodeSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, acs.ctx, "Select")
	if err := acs.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*AuthorizationCodeQuery, *AuthorizationCodeSelect](ctx, acs.AuthorizationCodeQuery, acs, acs.inters, v)
}

func (acs *AuthorizationCodeSelect) sqlScan(ctx context.Context, root *AuthorizationCodeQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(acs.fns))
	for _, fn := range acs.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*acs.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := acs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
