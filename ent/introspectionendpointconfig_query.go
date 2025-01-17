// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/introspectionendpointconfig"
	"go.authbricks.com/bricks/ent/predicate"
	"go.authbricks.com/bricks/ent/service"
)

// IntrospectionEndpointConfigQuery is the builder for querying IntrospectionEndpointConfig entities.
type IntrospectionEndpointConfigQuery struct {
	config
	ctx         *QueryContext
	order       []introspectionendpointconfig.OrderOption
	inters      []Interceptor
	predicates  []predicate.IntrospectionEndpointConfig
	withService *ServiceQuery
	withFKs     bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the IntrospectionEndpointConfigQuery builder.
func (iecq *IntrospectionEndpointConfigQuery) Where(ps ...predicate.IntrospectionEndpointConfig) *IntrospectionEndpointConfigQuery {
	iecq.predicates = append(iecq.predicates, ps...)
	return iecq
}

// Limit the number of records to be returned by this query.
func (iecq *IntrospectionEndpointConfigQuery) Limit(limit int) *IntrospectionEndpointConfigQuery {
	iecq.ctx.Limit = &limit
	return iecq
}

// Offset to start from.
func (iecq *IntrospectionEndpointConfigQuery) Offset(offset int) *IntrospectionEndpointConfigQuery {
	iecq.ctx.Offset = &offset
	return iecq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (iecq *IntrospectionEndpointConfigQuery) Unique(unique bool) *IntrospectionEndpointConfigQuery {
	iecq.ctx.Unique = &unique
	return iecq
}

// Order specifies how the records should be ordered.
func (iecq *IntrospectionEndpointConfigQuery) Order(o ...introspectionendpointconfig.OrderOption) *IntrospectionEndpointConfigQuery {
	iecq.order = append(iecq.order, o...)
	return iecq
}

// QueryService chains the current query on the "service" edge.
func (iecq *IntrospectionEndpointConfigQuery) QueryService() *ServiceQuery {
	query := (&ServiceClient{config: iecq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := iecq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := iecq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(introspectionendpointconfig.Table, introspectionendpointconfig.FieldID, selector),
			sqlgraph.To(service.Table, service.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, introspectionendpointconfig.ServiceTable, introspectionendpointconfig.ServiceColumn),
		)
		fromU = sqlgraph.SetNeighbors(iecq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first IntrospectionEndpointConfig entity from the query.
// Returns a *NotFoundError when no IntrospectionEndpointConfig was found.
func (iecq *IntrospectionEndpointConfigQuery) First(ctx context.Context) (*IntrospectionEndpointConfig, error) {
	nodes, err := iecq.Limit(1).All(setContextOp(ctx, iecq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{introspectionendpointconfig.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (iecq *IntrospectionEndpointConfigQuery) FirstX(ctx context.Context) *IntrospectionEndpointConfig {
	node, err := iecq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first IntrospectionEndpointConfig ID from the query.
// Returns a *NotFoundError when no IntrospectionEndpointConfig ID was found.
func (iecq *IntrospectionEndpointConfigQuery) FirstID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = iecq.Limit(1).IDs(setContextOp(ctx, iecq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{introspectionendpointconfig.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (iecq *IntrospectionEndpointConfigQuery) FirstIDX(ctx context.Context) string {
	id, err := iecq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single IntrospectionEndpointConfig entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one IntrospectionEndpointConfig entity is found.
// Returns a *NotFoundError when no IntrospectionEndpointConfig entities are found.
func (iecq *IntrospectionEndpointConfigQuery) Only(ctx context.Context) (*IntrospectionEndpointConfig, error) {
	nodes, err := iecq.Limit(2).All(setContextOp(ctx, iecq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{introspectionendpointconfig.Label}
	default:
		return nil, &NotSingularError{introspectionendpointconfig.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (iecq *IntrospectionEndpointConfigQuery) OnlyX(ctx context.Context) *IntrospectionEndpointConfig {
	node, err := iecq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only IntrospectionEndpointConfig ID in the query.
// Returns a *NotSingularError when more than one IntrospectionEndpointConfig ID is found.
// Returns a *NotFoundError when no entities are found.
func (iecq *IntrospectionEndpointConfigQuery) OnlyID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = iecq.Limit(2).IDs(setContextOp(ctx, iecq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{introspectionendpointconfig.Label}
	default:
		err = &NotSingularError{introspectionendpointconfig.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (iecq *IntrospectionEndpointConfigQuery) OnlyIDX(ctx context.Context) string {
	id, err := iecq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of IntrospectionEndpointConfigs.
func (iecq *IntrospectionEndpointConfigQuery) All(ctx context.Context) ([]*IntrospectionEndpointConfig, error) {
	ctx = setContextOp(ctx, iecq.ctx, "All")
	if err := iecq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*IntrospectionEndpointConfig, *IntrospectionEndpointConfigQuery]()
	return withInterceptors[[]*IntrospectionEndpointConfig](ctx, iecq, qr, iecq.inters)
}

// AllX is like All, but panics if an error occurs.
func (iecq *IntrospectionEndpointConfigQuery) AllX(ctx context.Context) []*IntrospectionEndpointConfig {
	nodes, err := iecq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of IntrospectionEndpointConfig IDs.
func (iecq *IntrospectionEndpointConfigQuery) IDs(ctx context.Context) (ids []string, err error) {
	if iecq.ctx.Unique == nil && iecq.path != nil {
		iecq.Unique(true)
	}
	ctx = setContextOp(ctx, iecq.ctx, "IDs")
	if err = iecq.Select(introspectionendpointconfig.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (iecq *IntrospectionEndpointConfigQuery) IDsX(ctx context.Context) []string {
	ids, err := iecq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (iecq *IntrospectionEndpointConfigQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, iecq.ctx, "Count")
	if err := iecq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, iecq, querierCount[*IntrospectionEndpointConfigQuery](), iecq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (iecq *IntrospectionEndpointConfigQuery) CountX(ctx context.Context) int {
	count, err := iecq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (iecq *IntrospectionEndpointConfigQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, iecq.ctx, "Exist")
	switch _, err := iecq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (iecq *IntrospectionEndpointConfigQuery) ExistX(ctx context.Context) bool {
	exist, err := iecq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the IntrospectionEndpointConfigQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (iecq *IntrospectionEndpointConfigQuery) Clone() *IntrospectionEndpointConfigQuery {
	if iecq == nil {
		return nil
	}
	return &IntrospectionEndpointConfigQuery{
		config:      iecq.config,
		ctx:         iecq.ctx.Clone(),
		order:       append([]introspectionendpointconfig.OrderOption{}, iecq.order...),
		inters:      append([]Interceptor{}, iecq.inters...),
		predicates:  append([]predicate.IntrospectionEndpointConfig{}, iecq.predicates...),
		withService: iecq.withService.Clone(),
		// clone intermediate query.
		sql:  iecq.sql.Clone(),
		path: iecq.path,
	}
}

// WithService tells the query-builder to eager-load the nodes that are connected to
// the "service" edge. The optional arguments are used to configure the query builder of the edge.
func (iecq *IntrospectionEndpointConfigQuery) WithService(opts ...func(*ServiceQuery)) *IntrospectionEndpointConfigQuery {
	query := (&ServiceClient{config: iecq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	iecq.withService = query
	return iecq
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
//	client.IntrospectionEndpointConfig.Query().
//		GroupBy(introspectionendpointconfig.FieldEndpoint).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (iecq *IntrospectionEndpointConfigQuery) GroupBy(field string, fields ...string) *IntrospectionEndpointConfigGroupBy {
	iecq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &IntrospectionEndpointConfigGroupBy{build: iecq}
	grbuild.flds = &iecq.ctx.Fields
	grbuild.label = introspectionendpointconfig.Label
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
//	client.IntrospectionEndpointConfig.Query().
//		Select(introspectionendpointconfig.FieldEndpoint).
//		Scan(ctx, &v)
func (iecq *IntrospectionEndpointConfigQuery) Select(fields ...string) *IntrospectionEndpointConfigSelect {
	iecq.ctx.Fields = append(iecq.ctx.Fields, fields...)
	sbuild := &IntrospectionEndpointConfigSelect{IntrospectionEndpointConfigQuery: iecq}
	sbuild.label = introspectionendpointconfig.Label
	sbuild.flds, sbuild.scan = &iecq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a IntrospectionEndpointConfigSelect configured with the given aggregations.
func (iecq *IntrospectionEndpointConfigQuery) Aggregate(fns ...AggregateFunc) *IntrospectionEndpointConfigSelect {
	return iecq.Select().Aggregate(fns...)
}

func (iecq *IntrospectionEndpointConfigQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range iecq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, iecq); err != nil {
				return err
			}
		}
	}
	for _, f := range iecq.ctx.Fields {
		if !introspectionendpointconfig.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if iecq.path != nil {
		prev, err := iecq.path(ctx)
		if err != nil {
			return err
		}
		iecq.sql = prev
	}
	return nil
}

func (iecq *IntrospectionEndpointConfigQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*IntrospectionEndpointConfig, error) {
	var (
		nodes       = []*IntrospectionEndpointConfig{}
		withFKs     = iecq.withFKs
		_spec       = iecq.querySpec()
		loadedTypes = [1]bool{
			iecq.withService != nil,
		}
	)
	if iecq.withService != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, introspectionendpointconfig.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*IntrospectionEndpointConfig).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &IntrospectionEndpointConfig{config: iecq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, iecq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := iecq.withService; query != nil {
		if err := iecq.loadService(ctx, query, nodes, nil,
			func(n *IntrospectionEndpointConfig, e *Service) { n.Edges.Service = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (iecq *IntrospectionEndpointConfigQuery) loadService(ctx context.Context, query *ServiceQuery, nodes []*IntrospectionEndpointConfig, init func(*IntrospectionEndpointConfig), assign func(*IntrospectionEndpointConfig, *Service)) error {
	ids := make([]string, 0, len(nodes))
	nodeids := make(map[string][]*IntrospectionEndpointConfig)
	for i := range nodes {
		if nodes[i].service_service_introspection_endpoint_config == nil {
			continue
		}
		fk := *nodes[i].service_service_introspection_endpoint_config
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
			return fmt.Errorf(`unexpected foreign-key "service_service_introspection_endpoint_config" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (iecq *IntrospectionEndpointConfigQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := iecq.querySpec()
	_spec.Node.Columns = iecq.ctx.Fields
	if len(iecq.ctx.Fields) > 0 {
		_spec.Unique = iecq.ctx.Unique != nil && *iecq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, iecq.driver, _spec)
}

func (iecq *IntrospectionEndpointConfigQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(introspectionendpointconfig.Table, introspectionendpointconfig.Columns, sqlgraph.NewFieldSpec(introspectionendpointconfig.FieldID, field.TypeString))
	_spec.From = iecq.sql
	if unique := iecq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if iecq.path != nil {
		_spec.Unique = true
	}
	if fields := iecq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, introspectionendpointconfig.FieldID)
		for i := range fields {
			if fields[i] != introspectionendpointconfig.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := iecq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := iecq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := iecq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := iecq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (iecq *IntrospectionEndpointConfigQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(iecq.driver.Dialect())
	t1 := builder.Table(introspectionendpointconfig.Table)
	columns := iecq.ctx.Fields
	if len(columns) == 0 {
		columns = introspectionendpointconfig.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if iecq.sql != nil {
		selector = iecq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if iecq.ctx.Unique != nil && *iecq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range iecq.predicates {
		p(selector)
	}
	for _, p := range iecq.order {
		p(selector)
	}
	if offset := iecq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := iecq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// IntrospectionEndpointConfigGroupBy is the group-by builder for IntrospectionEndpointConfig entities.
type IntrospectionEndpointConfigGroupBy struct {
	selector
	build *IntrospectionEndpointConfigQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (iecgb *IntrospectionEndpointConfigGroupBy) Aggregate(fns ...AggregateFunc) *IntrospectionEndpointConfigGroupBy {
	iecgb.fns = append(iecgb.fns, fns...)
	return iecgb
}

// Scan applies the selector query and scans the result into the given value.
func (iecgb *IntrospectionEndpointConfigGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, iecgb.build.ctx, "GroupBy")
	if err := iecgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*IntrospectionEndpointConfigQuery, *IntrospectionEndpointConfigGroupBy](ctx, iecgb.build, iecgb, iecgb.build.inters, v)
}

func (iecgb *IntrospectionEndpointConfigGroupBy) sqlScan(ctx context.Context, root *IntrospectionEndpointConfigQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(iecgb.fns))
	for _, fn := range iecgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*iecgb.flds)+len(iecgb.fns))
		for _, f := range *iecgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*iecgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := iecgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// IntrospectionEndpointConfigSelect is the builder for selecting fields of IntrospectionEndpointConfig entities.
type IntrospectionEndpointConfigSelect struct {
	*IntrospectionEndpointConfigQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (iecs *IntrospectionEndpointConfigSelect) Aggregate(fns ...AggregateFunc) *IntrospectionEndpointConfigSelect {
	iecs.fns = append(iecs.fns, fns...)
	return iecs
}

// Scan applies the selector query and scans the result into the given value.
func (iecs *IntrospectionEndpointConfigSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, iecs.ctx, "Select")
	if err := iecs.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*IntrospectionEndpointConfigQuery, *IntrospectionEndpointConfigSelect](ctx, iecs.IntrospectionEndpointConfigQuery, iecs, iecs.inters, v)
}

func (iecs *IntrospectionEndpointConfigSelect) sqlScan(ctx context.Context, root *IntrospectionEndpointConfigQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(iecs.fns))
	for _, fn := range iecs.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*iecs.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := iecs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
