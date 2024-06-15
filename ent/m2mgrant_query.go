// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/m2mgrant"
	"go.authbricks.com/bricks/ent/oauthclient"
	"go.authbricks.com/bricks/ent/predicate"
)

// M2MGrantQuery is the builder for querying M2MGrant entities.
type M2MGrantQuery struct {
	config
	ctx        *QueryContext
	order      []m2mgrant.OrderOption
	inters     []Interceptor
	predicates []predicate.M2MGrant
	withClient *OAuthClientQuery
	withFKs    bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the M2MGrantQuery builder.
func (mgq *M2MGrantQuery) Where(ps ...predicate.M2MGrant) *M2MGrantQuery {
	mgq.predicates = append(mgq.predicates, ps...)
	return mgq
}

// Limit the number of records to be returned by this query.
func (mgq *M2MGrantQuery) Limit(limit int) *M2MGrantQuery {
	mgq.ctx.Limit = &limit
	return mgq
}

// Offset to start from.
func (mgq *M2MGrantQuery) Offset(offset int) *M2MGrantQuery {
	mgq.ctx.Offset = &offset
	return mgq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (mgq *M2MGrantQuery) Unique(unique bool) *M2MGrantQuery {
	mgq.ctx.Unique = &unique
	return mgq
}

// Order specifies how the records should be ordered.
func (mgq *M2MGrantQuery) Order(o ...m2mgrant.OrderOption) *M2MGrantQuery {
	mgq.order = append(mgq.order, o...)
	return mgq
}

// QueryClient chains the current query on the "client" edge.
func (mgq *M2MGrantQuery) QueryClient() *OAuthClientQuery {
	query := (&OAuthClientClient{config: mgq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := mgq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := mgq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(m2mgrant.Table, m2mgrant.FieldID, selector),
			sqlgraph.To(oauthclient.Table, oauthclient.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, m2mgrant.ClientTable, m2mgrant.ClientColumn),
		)
		fromU = sqlgraph.SetNeighbors(mgq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first M2MGrant entity from the query.
// Returns a *NotFoundError when no M2MGrant was found.
func (mgq *M2MGrantQuery) First(ctx context.Context) (*M2MGrant, error) {
	nodes, err := mgq.Limit(1).All(setContextOp(ctx, mgq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{m2mgrant.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (mgq *M2MGrantQuery) FirstX(ctx context.Context) *M2MGrant {
	node, err := mgq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first M2MGrant ID from the query.
// Returns a *NotFoundError when no M2MGrant ID was found.
func (mgq *M2MGrantQuery) FirstID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = mgq.Limit(1).IDs(setContextOp(ctx, mgq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{m2mgrant.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (mgq *M2MGrantQuery) FirstIDX(ctx context.Context) string {
	id, err := mgq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single M2MGrant entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one M2MGrant entity is found.
// Returns a *NotFoundError when no M2MGrant entities are found.
func (mgq *M2MGrantQuery) Only(ctx context.Context) (*M2MGrant, error) {
	nodes, err := mgq.Limit(2).All(setContextOp(ctx, mgq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{m2mgrant.Label}
	default:
		return nil, &NotSingularError{m2mgrant.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (mgq *M2MGrantQuery) OnlyX(ctx context.Context) *M2MGrant {
	node, err := mgq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only M2MGrant ID in the query.
// Returns a *NotSingularError when more than one M2MGrant ID is found.
// Returns a *NotFoundError when no entities are found.
func (mgq *M2MGrantQuery) OnlyID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = mgq.Limit(2).IDs(setContextOp(ctx, mgq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{m2mgrant.Label}
	default:
		err = &NotSingularError{m2mgrant.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (mgq *M2MGrantQuery) OnlyIDX(ctx context.Context) string {
	id, err := mgq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of M2MGrants.
func (mgq *M2MGrantQuery) All(ctx context.Context) ([]*M2MGrant, error) {
	ctx = setContextOp(ctx, mgq.ctx, "All")
	if err := mgq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*M2MGrant, *M2MGrantQuery]()
	return withInterceptors[[]*M2MGrant](ctx, mgq, qr, mgq.inters)
}

// AllX is like All, but panics if an error occurs.
func (mgq *M2MGrantQuery) AllX(ctx context.Context) []*M2MGrant {
	nodes, err := mgq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of M2MGrant IDs.
func (mgq *M2MGrantQuery) IDs(ctx context.Context) (ids []string, err error) {
	if mgq.ctx.Unique == nil && mgq.path != nil {
		mgq.Unique(true)
	}
	ctx = setContextOp(ctx, mgq.ctx, "IDs")
	if err = mgq.Select(m2mgrant.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (mgq *M2MGrantQuery) IDsX(ctx context.Context) []string {
	ids, err := mgq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (mgq *M2MGrantQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, mgq.ctx, "Count")
	if err := mgq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, mgq, querierCount[*M2MGrantQuery](), mgq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (mgq *M2MGrantQuery) CountX(ctx context.Context) int {
	count, err := mgq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (mgq *M2MGrantQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, mgq.ctx, "Exist")
	switch _, err := mgq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (mgq *M2MGrantQuery) ExistX(ctx context.Context) bool {
	exist, err := mgq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the M2MGrantQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (mgq *M2MGrantQuery) Clone() *M2MGrantQuery {
	if mgq == nil {
		return nil
	}
	return &M2MGrantQuery{
		config:     mgq.config,
		ctx:        mgq.ctx.Clone(),
		order:      append([]m2mgrant.OrderOption{}, mgq.order...),
		inters:     append([]Interceptor{}, mgq.inters...),
		predicates: append([]predicate.M2MGrant{}, mgq.predicates...),
		withClient: mgq.withClient.Clone(),
		// clone intermediate query.
		sql:  mgq.sql.Clone(),
		path: mgq.path,
	}
}

// WithClient tells the query-builder to eager-load the nodes that are connected to
// the "client" edge. The optional arguments are used to configure the query builder of the edge.
func (mgq *M2MGrantQuery) WithClient(opts ...func(*OAuthClientQuery)) *M2MGrantQuery {
	query := (&OAuthClientClient{config: mgq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	mgq.withClient = query
	return mgq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		Scopes []string `json:"scopes"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.M2MGrant.Query().
//		GroupBy(m2mgrant.FieldScopes).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (mgq *M2MGrantQuery) GroupBy(field string, fields ...string) *M2MGrantGroupBy {
	mgq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &M2MGrantGroupBy{build: mgq}
	grbuild.flds = &mgq.ctx.Fields
	grbuild.label = m2mgrant.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		Scopes []string `json:"scopes"`
//	}
//
//	client.M2MGrant.Query().
//		Select(m2mgrant.FieldScopes).
//		Scan(ctx, &v)
func (mgq *M2MGrantQuery) Select(fields ...string) *M2MGrantSelect {
	mgq.ctx.Fields = append(mgq.ctx.Fields, fields...)
	sbuild := &M2MGrantSelect{M2MGrantQuery: mgq}
	sbuild.label = m2mgrant.Label
	sbuild.flds, sbuild.scan = &mgq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a M2MGrantSelect configured with the given aggregations.
func (mgq *M2MGrantQuery) Aggregate(fns ...AggregateFunc) *M2MGrantSelect {
	return mgq.Select().Aggregate(fns...)
}

func (mgq *M2MGrantQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range mgq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, mgq); err != nil {
				return err
			}
		}
	}
	for _, f := range mgq.ctx.Fields {
		if !m2mgrant.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if mgq.path != nil {
		prev, err := mgq.path(ctx)
		if err != nil {
			return err
		}
		mgq.sql = prev
	}
	return nil
}

func (mgq *M2MGrantQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*M2MGrant, error) {
	var (
		nodes       = []*M2MGrant{}
		withFKs     = mgq.withFKs
		_spec       = mgq.querySpec()
		loadedTypes = [1]bool{
			mgq.withClient != nil,
		}
	)
	if mgq.withClient != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, m2mgrant.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*M2MGrant).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &M2MGrant{config: mgq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, mgq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := mgq.withClient; query != nil {
		if err := mgq.loadClient(ctx, query, nodes, nil,
			func(n *M2MGrant, e *OAuthClient) { n.Edges.Client = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (mgq *M2MGrantQuery) loadClient(ctx context.Context, query *OAuthClientQuery, nodes []*M2MGrant, init func(*M2MGrant), assign func(*M2MGrant, *OAuthClient)) error {
	ids := make([]string, 0, len(nodes))
	nodeids := make(map[string][]*M2MGrant)
	for i := range nodes {
		if nodes[i].oauth_client_m2m_grants == nil {
			continue
		}
		fk := *nodes[i].oauth_client_m2m_grants
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(oauthclient.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "oauth_client_m2m_grants" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (mgq *M2MGrantQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := mgq.querySpec()
	_spec.Node.Columns = mgq.ctx.Fields
	if len(mgq.ctx.Fields) > 0 {
		_spec.Unique = mgq.ctx.Unique != nil && *mgq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, mgq.driver, _spec)
}

func (mgq *M2MGrantQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(m2mgrant.Table, m2mgrant.Columns, sqlgraph.NewFieldSpec(m2mgrant.FieldID, field.TypeString))
	_spec.From = mgq.sql
	if unique := mgq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if mgq.path != nil {
		_spec.Unique = true
	}
	if fields := mgq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, m2mgrant.FieldID)
		for i := range fields {
			if fields[i] != m2mgrant.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := mgq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := mgq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := mgq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := mgq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (mgq *M2MGrantQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(mgq.driver.Dialect())
	t1 := builder.Table(m2mgrant.Table)
	columns := mgq.ctx.Fields
	if len(columns) == 0 {
		columns = m2mgrant.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if mgq.sql != nil {
		selector = mgq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if mgq.ctx.Unique != nil && *mgq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range mgq.predicates {
		p(selector)
	}
	for _, p := range mgq.order {
		p(selector)
	}
	if offset := mgq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := mgq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// M2MGrantGroupBy is the group-by builder for M2MGrant entities.
type M2MGrantGroupBy struct {
	selector
	build *M2MGrantQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (mggb *M2MGrantGroupBy) Aggregate(fns ...AggregateFunc) *M2MGrantGroupBy {
	mggb.fns = append(mggb.fns, fns...)
	return mggb
}

// Scan applies the selector query and scans the result into the given value.
func (mggb *M2MGrantGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, mggb.build.ctx, "GroupBy")
	if err := mggb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*M2MGrantQuery, *M2MGrantGroupBy](ctx, mggb.build, mggb, mggb.build.inters, v)
}

func (mggb *M2MGrantGroupBy) sqlScan(ctx context.Context, root *M2MGrantQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(mggb.fns))
	for _, fn := range mggb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*mggb.flds)+len(mggb.fns))
		for _, f := range *mggb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*mggb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := mggb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// M2MGrantSelect is the builder for selecting fields of M2MGrant entities.
type M2MGrantSelect struct {
	*M2MGrantQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (mgs *M2MGrantSelect) Aggregate(fns ...AggregateFunc) *M2MGrantSelect {
	mgs.fns = append(mgs.fns, fns...)
	return mgs
}

// Scan applies the selector query and scans the result into the given value.
func (mgs *M2MGrantSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, mgs.ctx, "Select")
	if err := mgs.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*M2MGrantQuery, *M2MGrantSelect](ctx, mgs.M2MGrantQuery, mgs, mgs.inters, v)
}

func (mgs *M2MGrantSelect) sqlScan(ctx context.Context, root *M2MGrantQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(mgs.fns))
	for _, fn := range mgs.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*mgs.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := mgs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}