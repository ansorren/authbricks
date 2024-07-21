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
	"go.authbricks.com/bricks/ent/wellknownendpointconfig"
)

// WellKnownEndpointConfigQuery is the builder for querying WellKnownEndpointConfig entities.
type WellKnownEndpointConfigQuery struct {
	config
	ctx         *QueryContext
	order       []wellknownendpointconfig.OrderOption
	inters      []Interceptor
	predicates  []predicate.WellKnownEndpointConfig
	withService *ServiceQuery
	withFKs     bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the WellKnownEndpointConfigQuery builder.
func (wkecq *WellKnownEndpointConfigQuery) Where(ps ...predicate.WellKnownEndpointConfig) *WellKnownEndpointConfigQuery {
	wkecq.predicates = append(wkecq.predicates, ps...)
	return wkecq
}

// Limit the number of records to be returned by this query.
func (wkecq *WellKnownEndpointConfigQuery) Limit(limit int) *WellKnownEndpointConfigQuery {
	wkecq.ctx.Limit = &limit
	return wkecq
}

// Offset to start from.
func (wkecq *WellKnownEndpointConfigQuery) Offset(offset int) *WellKnownEndpointConfigQuery {
	wkecq.ctx.Offset = &offset
	return wkecq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (wkecq *WellKnownEndpointConfigQuery) Unique(unique bool) *WellKnownEndpointConfigQuery {
	wkecq.ctx.Unique = &unique
	return wkecq
}

// Order specifies how the records should be ordered.
func (wkecq *WellKnownEndpointConfigQuery) Order(o ...wellknownendpointconfig.OrderOption) *WellKnownEndpointConfigQuery {
	wkecq.order = append(wkecq.order, o...)
	return wkecq
}

// QueryService chains the current query on the "service" edge.
func (wkecq *WellKnownEndpointConfigQuery) QueryService() *ServiceQuery {
	query := (&ServiceClient{config: wkecq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := wkecq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := wkecq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(wellknownendpointconfig.Table, wellknownendpointconfig.FieldID, selector),
			sqlgraph.To(service.Table, service.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, wellknownendpointconfig.ServiceTable, wellknownendpointconfig.ServiceColumn),
		)
		fromU = sqlgraph.SetNeighbors(wkecq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first WellKnownEndpointConfig entity from the query.
// Returns a *NotFoundError when no WellKnownEndpointConfig was found.
func (wkecq *WellKnownEndpointConfigQuery) First(ctx context.Context) (*WellKnownEndpointConfig, error) {
	nodes, err := wkecq.Limit(1).All(setContextOp(ctx, wkecq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{wellknownendpointconfig.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (wkecq *WellKnownEndpointConfigQuery) FirstX(ctx context.Context) *WellKnownEndpointConfig {
	node, err := wkecq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first WellKnownEndpointConfig ID from the query.
// Returns a *NotFoundError when no WellKnownEndpointConfig ID was found.
func (wkecq *WellKnownEndpointConfigQuery) FirstID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = wkecq.Limit(1).IDs(setContextOp(ctx, wkecq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{wellknownendpointconfig.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (wkecq *WellKnownEndpointConfigQuery) FirstIDX(ctx context.Context) string {
	id, err := wkecq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single WellKnownEndpointConfig entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one WellKnownEndpointConfig entity is found.
// Returns a *NotFoundError when no WellKnownEndpointConfig entities are found.
func (wkecq *WellKnownEndpointConfigQuery) Only(ctx context.Context) (*WellKnownEndpointConfig, error) {
	nodes, err := wkecq.Limit(2).All(setContextOp(ctx, wkecq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{wellknownendpointconfig.Label}
	default:
		return nil, &NotSingularError{wellknownendpointconfig.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (wkecq *WellKnownEndpointConfigQuery) OnlyX(ctx context.Context) *WellKnownEndpointConfig {
	node, err := wkecq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only WellKnownEndpointConfig ID in the query.
// Returns a *NotSingularError when more than one WellKnownEndpointConfig ID is found.
// Returns a *NotFoundError when no entities are found.
func (wkecq *WellKnownEndpointConfigQuery) OnlyID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = wkecq.Limit(2).IDs(setContextOp(ctx, wkecq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{wellknownendpointconfig.Label}
	default:
		err = &NotSingularError{wellknownendpointconfig.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (wkecq *WellKnownEndpointConfigQuery) OnlyIDX(ctx context.Context) string {
	id, err := wkecq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of WellKnownEndpointConfigs.
func (wkecq *WellKnownEndpointConfigQuery) All(ctx context.Context) ([]*WellKnownEndpointConfig, error) {
	ctx = setContextOp(ctx, wkecq.ctx, "All")
	if err := wkecq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*WellKnownEndpointConfig, *WellKnownEndpointConfigQuery]()
	return withInterceptors[[]*WellKnownEndpointConfig](ctx, wkecq, qr, wkecq.inters)
}

// AllX is like All, but panics if an error occurs.
func (wkecq *WellKnownEndpointConfigQuery) AllX(ctx context.Context) []*WellKnownEndpointConfig {
	nodes, err := wkecq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of WellKnownEndpointConfig IDs.
func (wkecq *WellKnownEndpointConfigQuery) IDs(ctx context.Context) (ids []string, err error) {
	if wkecq.ctx.Unique == nil && wkecq.path != nil {
		wkecq.Unique(true)
	}
	ctx = setContextOp(ctx, wkecq.ctx, "IDs")
	if err = wkecq.Select(wellknownendpointconfig.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (wkecq *WellKnownEndpointConfigQuery) IDsX(ctx context.Context) []string {
	ids, err := wkecq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (wkecq *WellKnownEndpointConfigQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, wkecq.ctx, "Count")
	if err := wkecq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, wkecq, querierCount[*WellKnownEndpointConfigQuery](), wkecq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (wkecq *WellKnownEndpointConfigQuery) CountX(ctx context.Context) int {
	count, err := wkecq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (wkecq *WellKnownEndpointConfigQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, wkecq.ctx, "Exist")
	switch _, err := wkecq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (wkecq *WellKnownEndpointConfigQuery) ExistX(ctx context.Context) bool {
	exist, err := wkecq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the WellKnownEndpointConfigQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (wkecq *WellKnownEndpointConfigQuery) Clone() *WellKnownEndpointConfigQuery {
	if wkecq == nil {
		return nil
	}
	return &WellKnownEndpointConfigQuery{
		config:      wkecq.config,
		ctx:         wkecq.ctx.Clone(),
		order:       append([]wellknownendpointconfig.OrderOption{}, wkecq.order...),
		inters:      append([]Interceptor{}, wkecq.inters...),
		predicates:  append([]predicate.WellKnownEndpointConfig{}, wkecq.predicates...),
		withService: wkecq.withService.Clone(),
		// clone intermediate query.
		sql:  wkecq.sql.Clone(),
		path: wkecq.path,
	}
}

// WithService tells the query-builder to eager-load the nodes that are connected to
// the "service" edge. The optional arguments are used to configure the query builder of the edge.
func (wkecq *WellKnownEndpointConfigQuery) WithService(opts ...func(*ServiceQuery)) *WellKnownEndpointConfigQuery {
	query := (&ServiceClient{config: wkecq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	wkecq.withService = query
	return wkecq
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
//	client.WellKnownEndpointConfig.Query().
//		GroupBy(wellknownendpointconfig.FieldEndpoint).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (wkecq *WellKnownEndpointConfigQuery) GroupBy(field string, fields ...string) *WellKnownEndpointConfigGroupBy {
	wkecq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &WellKnownEndpointConfigGroupBy{build: wkecq}
	grbuild.flds = &wkecq.ctx.Fields
	grbuild.label = wellknownendpointconfig.Label
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
//	client.WellKnownEndpointConfig.Query().
//		Select(wellknownendpointconfig.FieldEndpoint).
//		Scan(ctx, &v)
func (wkecq *WellKnownEndpointConfigQuery) Select(fields ...string) *WellKnownEndpointConfigSelect {
	wkecq.ctx.Fields = append(wkecq.ctx.Fields, fields...)
	sbuild := &WellKnownEndpointConfigSelect{WellKnownEndpointConfigQuery: wkecq}
	sbuild.label = wellknownendpointconfig.Label
	sbuild.flds, sbuild.scan = &wkecq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a WellKnownEndpointConfigSelect configured with the given aggregations.
func (wkecq *WellKnownEndpointConfigQuery) Aggregate(fns ...AggregateFunc) *WellKnownEndpointConfigSelect {
	return wkecq.Select().Aggregate(fns...)
}

func (wkecq *WellKnownEndpointConfigQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range wkecq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, wkecq); err != nil {
				return err
			}
		}
	}
	for _, f := range wkecq.ctx.Fields {
		if !wellknownendpointconfig.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if wkecq.path != nil {
		prev, err := wkecq.path(ctx)
		if err != nil {
			return err
		}
		wkecq.sql = prev
	}
	return nil
}

func (wkecq *WellKnownEndpointConfigQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*WellKnownEndpointConfig, error) {
	var (
		nodes       = []*WellKnownEndpointConfig{}
		withFKs     = wkecq.withFKs
		_spec       = wkecq.querySpec()
		loadedTypes = [1]bool{
			wkecq.withService != nil,
		}
	)
	if wkecq.withService != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, wellknownendpointconfig.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*WellKnownEndpointConfig).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &WellKnownEndpointConfig{config: wkecq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, wkecq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := wkecq.withService; query != nil {
		if err := wkecq.loadService(ctx, query, nodes, nil,
			func(n *WellKnownEndpointConfig, e *Service) { n.Edges.Service = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (wkecq *WellKnownEndpointConfigQuery) loadService(ctx context.Context, query *ServiceQuery, nodes []*WellKnownEndpointConfig, init func(*WellKnownEndpointConfig), assign func(*WellKnownEndpointConfig, *Service)) error {
	ids := make([]string, 0, len(nodes))
	nodeids := make(map[string][]*WellKnownEndpointConfig)
	for i := range nodes {
		if nodes[i].service_service_well_known_endpoint_config == nil {
			continue
		}
		fk := *nodes[i].service_service_well_known_endpoint_config
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
			return fmt.Errorf(`unexpected foreign-key "service_service_well_known_endpoint_config" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (wkecq *WellKnownEndpointConfigQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := wkecq.querySpec()
	_spec.Node.Columns = wkecq.ctx.Fields
	if len(wkecq.ctx.Fields) > 0 {
		_spec.Unique = wkecq.ctx.Unique != nil && *wkecq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, wkecq.driver, _spec)
}

func (wkecq *WellKnownEndpointConfigQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(wellknownendpointconfig.Table, wellknownendpointconfig.Columns, sqlgraph.NewFieldSpec(wellknownendpointconfig.FieldID, field.TypeString))
	_spec.From = wkecq.sql
	if unique := wkecq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if wkecq.path != nil {
		_spec.Unique = true
	}
	if fields := wkecq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, wellknownendpointconfig.FieldID)
		for i := range fields {
			if fields[i] != wellknownendpointconfig.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := wkecq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := wkecq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := wkecq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := wkecq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (wkecq *WellKnownEndpointConfigQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(wkecq.driver.Dialect())
	t1 := builder.Table(wellknownendpointconfig.Table)
	columns := wkecq.ctx.Fields
	if len(columns) == 0 {
		columns = wellknownendpointconfig.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if wkecq.sql != nil {
		selector = wkecq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if wkecq.ctx.Unique != nil && *wkecq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range wkecq.predicates {
		p(selector)
	}
	for _, p := range wkecq.order {
		p(selector)
	}
	if offset := wkecq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := wkecq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// WellKnownEndpointConfigGroupBy is the group-by builder for WellKnownEndpointConfig entities.
type WellKnownEndpointConfigGroupBy struct {
	selector
	build *WellKnownEndpointConfigQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (wkecgb *WellKnownEndpointConfigGroupBy) Aggregate(fns ...AggregateFunc) *WellKnownEndpointConfigGroupBy {
	wkecgb.fns = append(wkecgb.fns, fns...)
	return wkecgb
}

// Scan applies the selector query and scans the result into the given value.
func (wkecgb *WellKnownEndpointConfigGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, wkecgb.build.ctx, "GroupBy")
	if err := wkecgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*WellKnownEndpointConfigQuery, *WellKnownEndpointConfigGroupBy](ctx, wkecgb.build, wkecgb, wkecgb.build.inters, v)
}

func (wkecgb *WellKnownEndpointConfigGroupBy) sqlScan(ctx context.Context, root *WellKnownEndpointConfigQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(wkecgb.fns))
	for _, fn := range wkecgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*wkecgb.flds)+len(wkecgb.fns))
		for _, f := range *wkecgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*wkecgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := wkecgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// WellKnownEndpointConfigSelect is the builder for selecting fields of WellKnownEndpointConfig entities.
type WellKnownEndpointConfigSelect struct {
	*WellKnownEndpointConfigQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (wkecs *WellKnownEndpointConfigSelect) Aggregate(fns ...AggregateFunc) *WellKnownEndpointConfigSelect {
	wkecs.fns = append(wkecs.fns, fns...)
	return wkecs
}

// Scan applies the selector query and scans the result into the given value.
func (wkecs *WellKnownEndpointConfigSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, wkecs.ctx, "Select")
	if err := wkecs.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*WellKnownEndpointConfigQuery, *WellKnownEndpointConfigSelect](ctx, wkecs.WellKnownEndpointConfigQuery, wkecs, wkecs.inters, v)
}

func (wkecs *WellKnownEndpointConfigSelect) sqlScan(ctx context.Context, root *WellKnownEndpointConfigQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(wkecs.fns))
	for _, fn := range wkecs.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*wkecs.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := wkecs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
