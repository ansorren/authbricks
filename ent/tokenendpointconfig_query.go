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
	"go.authbricks.com/bricks/ent/service"
	"go.authbricks.com/bricks/ent/tokenendpointconfig"
)

// TokenEndpointConfigQuery is the builder for querying TokenEndpointConfig entities.
type TokenEndpointConfigQuery struct {
	config
	ctx         *QueryContext
	order       []tokenendpointconfig.OrderOption
	inters      []Interceptor
	predicates  []predicate.TokenEndpointConfig
	withService *ServiceQuery
	withFKs     bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the TokenEndpointConfigQuery builder.
func (tecq *TokenEndpointConfigQuery) Where(ps ...predicate.TokenEndpointConfig) *TokenEndpointConfigQuery {
	tecq.predicates = append(tecq.predicates, ps...)
	return tecq
}

// Limit the number of records to be returned by this query.
func (tecq *TokenEndpointConfigQuery) Limit(limit int) *TokenEndpointConfigQuery {
	tecq.ctx.Limit = &limit
	return tecq
}

// Offset to start from.
func (tecq *TokenEndpointConfigQuery) Offset(offset int) *TokenEndpointConfigQuery {
	tecq.ctx.Offset = &offset
	return tecq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (tecq *TokenEndpointConfigQuery) Unique(unique bool) *TokenEndpointConfigQuery {
	tecq.ctx.Unique = &unique
	return tecq
}

// Order specifies how the records should be ordered.
func (tecq *TokenEndpointConfigQuery) Order(o ...tokenendpointconfig.OrderOption) *TokenEndpointConfigQuery {
	tecq.order = append(tecq.order, o...)
	return tecq
}

// QueryService chains the current query on the "service" edge.
func (tecq *TokenEndpointConfigQuery) QueryService() *ServiceQuery {
	query := (&ServiceClient{config: tecq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := tecq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := tecq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(tokenendpointconfig.Table, tokenendpointconfig.FieldID, selector),
			sqlgraph.To(service.Table, service.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, tokenendpointconfig.ServiceTable, tokenendpointconfig.ServiceColumn),
		)
		fromU = sqlgraph.SetNeighbors(tecq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first TokenEndpointConfig entity from the query.
// Returns a *NotFoundError when no TokenEndpointConfig was found.
func (tecq *TokenEndpointConfigQuery) First(ctx context.Context) (*TokenEndpointConfig, error) {
	nodes, err := tecq.Limit(1).All(setContextOp(ctx, tecq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{tokenendpointconfig.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (tecq *TokenEndpointConfigQuery) FirstX(ctx context.Context) *TokenEndpointConfig {
	node, err := tecq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first TokenEndpointConfig ID from the query.
// Returns a *NotFoundError when no TokenEndpointConfig ID was found.
func (tecq *TokenEndpointConfigQuery) FirstID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = tecq.Limit(1).IDs(setContextOp(ctx, tecq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{tokenendpointconfig.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (tecq *TokenEndpointConfigQuery) FirstIDX(ctx context.Context) string {
	id, err := tecq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single TokenEndpointConfig entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one TokenEndpointConfig entity is found.
// Returns a *NotFoundError when no TokenEndpointConfig entities are found.
func (tecq *TokenEndpointConfigQuery) Only(ctx context.Context) (*TokenEndpointConfig, error) {
	nodes, err := tecq.Limit(2).All(setContextOp(ctx, tecq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{tokenendpointconfig.Label}
	default:
		return nil, &NotSingularError{tokenendpointconfig.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (tecq *TokenEndpointConfigQuery) OnlyX(ctx context.Context) *TokenEndpointConfig {
	node, err := tecq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only TokenEndpointConfig ID in the query.
// Returns a *NotSingularError when more than one TokenEndpointConfig ID is found.
// Returns a *NotFoundError when no entities are found.
func (tecq *TokenEndpointConfigQuery) OnlyID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = tecq.Limit(2).IDs(setContextOp(ctx, tecq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{tokenendpointconfig.Label}
	default:
		err = &NotSingularError{tokenendpointconfig.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (tecq *TokenEndpointConfigQuery) OnlyIDX(ctx context.Context) string {
	id, err := tecq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of TokenEndpointConfigs.
func (tecq *TokenEndpointConfigQuery) All(ctx context.Context) ([]*TokenEndpointConfig, error) {
	ctx = setContextOp(ctx, tecq.ctx, "All")
	if err := tecq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*TokenEndpointConfig, *TokenEndpointConfigQuery]()
	return withInterceptors[[]*TokenEndpointConfig](ctx, tecq, qr, tecq.inters)
}

// AllX is like All, but panics if an error occurs.
func (tecq *TokenEndpointConfigQuery) AllX(ctx context.Context) []*TokenEndpointConfig {
	nodes, err := tecq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of TokenEndpointConfig IDs.
func (tecq *TokenEndpointConfigQuery) IDs(ctx context.Context) (ids []string, err error) {
	if tecq.ctx.Unique == nil && tecq.path != nil {
		tecq.Unique(true)
	}
	ctx = setContextOp(ctx, tecq.ctx, "IDs")
	if err = tecq.Select(tokenendpointconfig.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (tecq *TokenEndpointConfigQuery) IDsX(ctx context.Context) []string {
	ids, err := tecq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (tecq *TokenEndpointConfigQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, tecq.ctx, "Count")
	if err := tecq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, tecq, querierCount[*TokenEndpointConfigQuery](), tecq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (tecq *TokenEndpointConfigQuery) CountX(ctx context.Context) int {
	count, err := tecq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (tecq *TokenEndpointConfigQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, tecq.ctx, "Exist")
	switch _, err := tecq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (tecq *TokenEndpointConfigQuery) ExistX(ctx context.Context) bool {
	exist, err := tecq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the TokenEndpointConfigQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (tecq *TokenEndpointConfigQuery) Clone() *TokenEndpointConfigQuery {
	if tecq == nil {
		return nil
	}
	return &TokenEndpointConfigQuery{
		config:      tecq.config,
		ctx:         tecq.ctx.Clone(),
		order:       append([]tokenendpointconfig.OrderOption{}, tecq.order...),
		inters:      append([]Interceptor{}, tecq.inters...),
		predicates:  append([]predicate.TokenEndpointConfig{}, tecq.predicates...),
		withService: tecq.withService.Clone(),
		// clone intermediate query.
		sql:  tecq.sql.Clone(),
		path: tecq.path,
	}
}

// WithService tells the query-builder to eager-load the nodes that are connected to
// the "service" edge. The optional arguments are used to configure the query builder of the edge.
func (tecq *TokenEndpointConfigQuery) WithService(opts ...func(*ServiceQuery)) *TokenEndpointConfigQuery {
	query := (&ServiceClient{config: tecq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	tecq.withService = query
	return tecq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		Endpoint string `json:"endpoint" hcl:"endpoint"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.TokenEndpointConfig.Query().
//		GroupBy(tokenendpointconfig.FieldEndpoint).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (tecq *TokenEndpointConfigQuery) GroupBy(field string, fields ...string) *TokenEndpointConfigGroupBy {
	tecq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &TokenEndpointConfigGroupBy{build: tecq}
	grbuild.flds = &tecq.ctx.Fields
	grbuild.label = tokenendpointconfig.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		Endpoint string `json:"endpoint" hcl:"endpoint"`
//	}
//
//	client.TokenEndpointConfig.Query().
//		Select(tokenendpointconfig.FieldEndpoint).
//		Scan(ctx, &v)
func (tecq *TokenEndpointConfigQuery) Select(fields ...string) *TokenEndpointConfigSelect {
	tecq.ctx.Fields = append(tecq.ctx.Fields, fields...)
	sbuild := &TokenEndpointConfigSelect{TokenEndpointConfigQuery: tecq}
	sbuild.label = tokenendpointconfig.Label
	sbuild.flds, sbuild.scan = &tecq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a TokenEndpointConfigSelect configured with the given aggregations.
func (tecq *TokenEndpointConfigQuery) Aggregate(fns ...AggregateFunc) *TokenEndpointConfigSelect {
	return tecq.Select().Aggregate(fns...)
}

func (tecq *TokenEndpointConfigQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range tecq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, tecq); err != nil {
				return err
			}
		}
	}
	for _, f := range tecq.ctx.Fields {
		if !tokenendpointconfig.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if tecq.path != nil {
		prev, err := tecq.path(ctx)
		if err != nil {
			return err
		}
		tecq.sql = prev
	}
	return nil
}

func (tecq *TokenEndpointConfigQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*TokenEndpointConfig, error) {
	var (
		nodes       = []*TokenEndpointConfig{}
		withFKs     = tecq.withFKs
		_spec       = tecq.querySpec()
		loadedTypes = [1]bool{
			tecq.withService != nil,
		}
	)
	if tecq.withService != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, tokenendpointconfig.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*TokenEndpointConfig).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &TokenEndpointConfig{config: tecq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, tecq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := tecq.withService; query != nil {
		if err := tecq.loadService(ctx, query, nodes, nil,
			func(n *TokenEndpointConfig, e *Service) { n.Edges.Service = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (tecq *TokenEndpointConfigQuery) loadService(ctx context.Context, query *ServiceQuery, nodes []*TokenEndpointConfig, init func(*TokenEndpointConfig), assign func(*TokenEndpointConfig, *Service)) error {
	ids := make([]string, 0, len(nodes))
	nodeids := make(map[string][]*TokenEndpointConfig)
	for i := range nodes {
		if nodes[i].service_service_token_endpoint_config == nil {
			continue
		}
		fk := *nodes[i].service_service_token_endpoint_config
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(service.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "service_service_token_endpoint_config" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (tecq *TokenEndpointConfigQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := tecq.querySpec()
	_spec.Node.Columns = tecq.ctx.Fields
	if len(tecq.ctx.Fields) > 0 {
		_spec.Unique = tecq.ctx.Unique != nil && *tecq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, tecq.driver, _spec)
}

func (tecq *TokenEndpointConfigQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(tokenendpointconfig.Table, tokenendpointconfig.Columns, sqlgraph.NewFieldSpec(tokenendpointconfig.FieldID, field.TypeString))
	_spec.From = tecq.sql
	if unique := tecq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if tecq.path != nil {
		_spec.Unique = true
	}
	if fields := tecq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, tokenendpointconfig.FieldID)
		for i := range fields {
			if fields[i] != tokenendpointconfig.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := tecq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := tecq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := tecq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := tecq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (tecq *TokenEndpointConfigQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(tecq.driver.Dialect())
	t1 := builder.Table(tokenendpointconfig.Table)
	columns := tecq.ctx.Fields
	if len(columns) == 0 {
		columns = tokenendpointconfig.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if tecq.sql != nil {
		selector = tecq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if tecq.ctx.Unique != nil && *tecq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range tecq.predicates {
		p(selector)
	}
	for _, p := range tecq.order {
		p(selector)
	}
	if offset := tecq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := tecq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// TokenEndpointConfigGroupBy is the group-by builder for TokenEndpointConfig entities.
type TokenEndpointConfigGroupBy struct {
	selector
	build *TokenEndpointConfigQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (tecgb *TokenEndpointConfigGroupBy) Aggregate(fns ...AggregateFunc) *TokenEndpointConfigGroupBy {
	tecgb.fns = append(tecgb.fns, fns...)
	return tecgb
}

// Scan applies the selector query and scans the result into the given value.
func (tecgb *TokenEndpointConfigGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, tecgb.build.ctx, "GroupBy")
	if err := tecgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*TokenEndpointConfigQuery, *TokenEndpointConfigGroupBy](ctx, tecgb.build, tecgb, tecgb.build.inters, v)
}

func (tecgb *TokenEndpointConfigGroupBy) sqlScan(ctx context.Context, root *TokenEndpointConfigQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(tecgb.fns))
	for _, fn := range tecgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*tecgb.flds)+len(tecgb.fns))
		for _, f := range *tecgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*tecgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := tecgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// TokenEndpointConfigSelect is the builder for selecting fields of TokenEndpointConfig entities.
type TokenEndpointConfigSelect struct {
	*TokenEndpointConfigQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (tecs *TokenEndpointConfigSelect) Aggregate(fns ...AggregateFunc) *TokenEndpointConfigSelect {
	tecs.fns = append(tecs.fns, fns...)
	return tecs
}

// Scan applies the selector query and scans the result into the given value.
func (tecs *TokenEndpointConfigSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, tecs.ctx, "Select")
	if err := tecs.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*TokenEndpointConfigQuery, *TokenEndpointConfigSelect](ctx, tecs.TokenEndpointConfigQuery, tecs, tecs.inters, v)
}

func (tecs *TokenEndpointConfigSelect) sqlScan(ctx context.Context, root *TokenEndpointConfigQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(tecs.fns))
	for _, fn := range tecs.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*tecs.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := tecs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
