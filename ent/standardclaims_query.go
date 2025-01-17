// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/predicate"
	"go.authbricks.com/bricks/ent/standardclaims"
	"go.authbricks.com/bricks/ent/user"
)

// StandardClaimsQuery is the builder for querying StandardClaims entities.
type StandardClaimsQuery struct {
	config
	ctx        *QueryContext
	order      []standardclaims.OrderOption
	inters     []Interceptor
	predicates []predicate.StandardClaims
	withUser   *UserQuery
	withFKs    bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the StandardClaimsQuery builder.
func (scq *StandardClaimsQuery) Where(ps ...predicate.StandardClaims) *StandardClaimsQuery {
	scq.predicates = append(scq.predicates, ps...)
	return scq
}

// Limit the number of records to be returned by this query.
func (scq *StandardClaimsQuery) Limit(limit int) *StandardClaimsQuery {
	scq.ctx.Limit = &limit
	return scq
}

// Offset to start from.
func (scq *StandardClaimsQuery) Offset(offset int) *StandardClaimsQuery {
	scq.ctx.Offset = &offset
	return scq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (scq *StandardClaimsQuery) Unique(unique bool) *StandardClaimsQuery {
	scq.ctx.Unique = &unique
	return scq
}

// Order specifies how the records should be ordered.
func (scq *StandardClaimsQuery) Order(o ...standardclaims.OrderOption) *StandardClaimsQuery {
	scq.order = append(scq.order, o...)
	return scq
}

// QueryUser chains the current query on the "user" edge.
func (scq *StandardClaimsQuery) QueryUser() *UserQuery {
	query := (&UserClient{config: scq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := scq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := scq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(standardclaims.Table, standardclaims.FieldID, selector),
			sqlgraph.To(user.Table, user.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, standardclaims.UserTable, standardclaims.UserColumn),
		)
		fromU = sqlgraph.SetNeighbors(scq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first StandardClaims entity from the query.
// Returns a *NotFoundError when no StandardClaims was found.
func (scq *StandardClaimsQuery) First(ctx context.Context) (*StandardClaims, error) {
	nodes, err := scq.Limit(1).All(setContextOp(ctx, scq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{standardclaims.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (scq *StandardClaimsQuery) FirstX(ctx context.Context) *StandardClaims {
	node, err := scq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first StandardClaims ID from the query.
// Returns a *NotFoundError when no StandardClaims ID was found.
func (scq *StandardClaimsQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = scq.Limit(1).IDs(setContextOp(ctx, scq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{standardclaims.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (scq *StandardClaimsQuery) FirstIDX(ctx context.Context) int {
	id, err := scq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single StandardClaims entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one StandardClaims entity is found.
// Returns a *NotFoundError when no StandardClaims entities are found.
func (scq *StandardClaimsQuery) Only(ctx context.Context) (*StandardClaims, error) {
	nodes, err := scq.Limit(2).All(setContextOp(ctx, scq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{standardclaims.Label}
	default:
		return nil, &NotSingularError{standardclaims.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (scq *StandardClaimsQuery) OnlyX(ctx context.Context) *StandardClaims {
	node, err := scq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only StandardClaims ID in the query.
// Returns a *NotSingularError when more than one StandardClaims ID is found.
// Returns a *NotFoundError when no entities are found.
func (scq *StandardClaimsQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = scq.Limit(2).IDs(setContextOp(ctx, scq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{standardclaims.Label}
	default:
		err = &NotSingularError{standardclaims.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (scq *StandardClaimsQuery) OnlyIDX(ctx context.Context) int {
	id, err := scq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of StandardClaimsSlice.
func (scq *StandardClaimsQuery) All(ctx context.Context) ([]*StandardClaims, error) {
	ctx = setContextOp(ctx, scq.ctx, "All")
	if err := scq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*StandardClaims, *StandardClaimsQuery]()
	return withInterceptors[[]*StandardClaims](ctx, scq, qr, scq.inters)
}

// AllX is like All, but panics if an error occurs.
func (scq *StandardClaimsQuery) AllX(ctx context.Context) []*StandardClaims {
	nodes, err := scq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of StandardClaims IDs.
func (scq *StandardClaimsQuery) IDs(ctx context.Context) (ids []int, err error) {
	if scq.ctx.Unique == nil && scq.path != nil {
		scq.Unique(true)
	}
	ctx = setContextOp(ctx, scq.ctx, "IDs")
	if err = scq.Select(standardclaims.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (scq *StandardClaimsQuery) IDsX(ctx context.Context) []int {
	ids, err := scq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (scq *StandardClaimsQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, scq.ctx, "Count")
	if err := scq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, scq, querierCount[*StandardClaimsQuery](), scq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (scq *StandardClaimsQuery) CountX(ctx context.Context) int {
	count, err := scq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (scq *StandardClaimsQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, scq.ctx, "Exist")
	switch _, err := scq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (scq *StandardClaimsQuery) ExistX(ctx context.Context) bool {
	exist, err := scq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the StandardClaimsQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (scq *StandardClaimsQuery) Clone() *StandardClaimsQuery {
	if scq == nil {
		return nil
	}
	return &StandardClaimsQuery{
		config:     scq.config,
		ctx:        scq.ctx.Clone(),
		order:      append([]standardclaims.OrderOption{}, scq.order...),
		inters:     append([]Interceptor{}, scq.inters...),
		predicates: append([]predicate.StandardClaims{}, scq.predicates...),
		withUser:   scq.withUser.Clone(),
		// clone intermediate query.
		sql:  scq.sql.Clone(),
		path: scq.path,
	}
}

// WithUser tells the query-builder to eager-load the nodes that are connected to
// the "user" edge. The optional arguments are used to configure the query builder of the edge.
func (scq *StandardClaimsQuery) WithUser(opts ...func(*UserQuery)) *StandardClaimsQuery {
	query := (&UserClient{config: scq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	scq.withUser = query
	return scq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		Subject string `json:"sub"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.StandardClaims.Query().
//		GroupBy(standardclaims.FieldSubject).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (scq *StandardClaimsQuery) GroupBy(field string, fields ...string) *StandardClaimsGroupBy {
	scq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &StandardClaimsGroupBy{build: scq}
	grbuild.flds = &scq.ctx.Fields
	grbuild.label = standardclaims.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		Subject string `json:"sub"`
//	}
//
//	client.StandardClaims.Query().
//		Select(standardclaims.FieldSubject).
//		Scan(ctx, &v)
func (scq *StandardClaimsQuery) Select(fields ...string) *StandardClaimsSelect {
	scq.ctx.Fields = append(scq.ctx.Fields, fields...)
	sbuild := &StandardClaimsSelect{StandardClaimsQuery: scq}
	sbuild.label = standardclaims.Label
	sbuild.flds, sbuild.scan = &scq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a StandardClaimsSelect configured with the given aggregations.
func (scq *StandardClaimsQuery) Aggregate(fns ...AggregateFunc) *StandardClaimsSelect {
	return scq.Select().Aggregate(fns...)
}

func (scq *StandardClaimsQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range scq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, scq); err != nil {
				return err
			}
		}
	}
	for _, f := range scq.ctx.Fields {
		if !standardclaims.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if scq.path != nil {
		prev, err := scq.path(ctx)
		if err != nil {
			return err
		}
		scq.sql = prev
	}
	return nil
}

func (scq *StandardClaimsQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*StandardClaims, error) {
	var (
		nodes       = []*StandardClaims{}
		withFKs     = scq.withFKs
		_spec       = scq.querySpec()
		loadedTypes = [1]bool{
			scq.withUser != nil,
		}
	)
	if scq.withUser != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, standardclaims.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*StandardClaims).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &StandardClaims{config: scq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, scq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := scq.withUser; query != nil {
		if err := scq.loadUser(ctx, query, nodes, nil,
			func(n *StandardClaims, e *User) { n.Edges.User = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (scq *StandardClaimsQuery) loadUser(ctx context.Context, query *UserQuery, nodes []*StandardClaims, init func(*StandardClaims), assign func(*StandardClaims, *User)) error {
	ids := make([]string, 0, len(nodes))
	nodeids := make(map[string][]*StandardClaims)
	for i := range nodes {
		if nodes[i].user_standard_claims == nil {
			continue
		}
		fk := *nodes[i].user_standard_claims
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(user.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "user_standard_claims" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (scq *StandardClaimsQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := scq.querySpec()
	_spec.Node.Columns = scq.ctx.Fields
	if len(scq.ctx.Fields) > 0 {
		_spec.Unique = scq.ctx.Unique != nil && *scq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, scq.driver, _spec)
}

func (scq *StandardClaimsQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(standardclaims.Table, standardclaims.Columns, sqlgraph.NewFieldSpec(standardclaims.FieldID, field.TypeInt))
	_spec.From = scq.sql
	if unique := scq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if scq.path != nil {
		_spec.Unique = true
	}
	if fields := scq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, standardclaims.FieldID)
		for i := range fields {
			if fields[i] != standardclaims.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := scq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := scq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := scq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := scq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (scq *StandardClaimsQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(scq.driver.Dialect())
	t1 := builder.Table(standardclaims.Table)
	columns := scq.ctx.Fields
	if len(columns) == 0 {
		columns = standardclaims.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if scq.sql != nil {
		selector = scq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if scq.ctx.Unique != nil && *scq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range scq.predicates {
		p(selector)
	}
	for _, p := range scq.order {
		p(selector)
	}
	if offset := scq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := scq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// StandardClaimsGroupBy is the group-by builder for StandardClaims entities.
type StandardClaimsGroupBy struct {
	selector
	build *StandardClaimsQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (scgb *StandardClaimsGroupBy) Aggregate(fns ...AggregateFunc) *StandardClaimsGroupBy {
	scgb.fns = append(scgb.fns, fns...)
	return scgb
}

// Scan applies the selector query and scans the result into the given value.
func (scgb *StandardClaimsGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, scgb.build.ctx, "GroupBy")
	if err := scgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*StandardClaimsQuery, *StandardClaimsGroupBy](ctx, scgb.build, scgb, scgb.build.inters, v)
}

func (scgb *StandardClaimsGroupBy) sqlScan(ctx context.Context, root *StandardClaimsQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(scgb.fns))
	for _, fn := range scgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*scgb.flds)+len(scgb.fns))
		for _, f := range *scgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*scgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := scgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// StandardClaimsSelect is the builder for selecting fields of StandardClaims entities.
type StandardClaimsSelect struct {
	*StandardClaimsQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (scs *StandardClaimsSelect) Aggregate(fns ...AggregateFunc) *StandardClaimsSelect {
	scs.fns = append(scs.fns, fns...)
	return scs
}

// Scan applies the selector query and scans the result into the given value.
func (scs *StandardClaimsSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, scs.ctx, "Select")
	if err := scs.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*StandardClaimsQuery, *StandardClaimsSelect](ctx, scs.StandardClaimsQuery, scs, scs.inters, v)
}

func (scs *StandardClaimsSelect) sqlScan(ctx context.Context, root *StandardClaimsQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(scs.fns))
	for _, fn := range scs.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*scs.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := scs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
