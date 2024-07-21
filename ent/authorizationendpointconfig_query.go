// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/authorizationendpointconfig"
	"go.authbricks.com/bricks/ent/predicate"
	"go.authbricks.com/bricks/ent/service"
)

// AuthorizationEndpointConfigQuery is the builder for querying AuthorizationEndpointConfig entities.
type AuthorizationEndpointConfigQuery struct {
	config
	ctx         *QueryContext
	order       []authorizationendpointconfig.OrderOption
	inters      []Interceptor
	predicates  []predicate.AuthorizationEndpointConfig
	withService *ServiceQuery
	withFKs     bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the AuthorizationEndpointConfigQuery builder.
func (aecq *AuthorizationEndpointConfigQuery) Where(ps ...predicate.AuthorizationEndpointConfig) *AuthorizationEndpointConfigQuery {
	aecq.predicates = append(aecq.predicates, ps...)
	return aecq
}

// Limit the number of records to be returned by this query.
func (aecq *AuthorizationEndpointConfigQuery) Limit(limit int) *AuthorizationEndpointConfigQuery {
	aecq.ctx.Limit = &limit
	return aecq
}

// Offset to start from.
func (aecq *AuthorizationEndpointConfigQuery) Offset(offset int) *AuthorizationEndpointConfigQuery {
	aecq.ctx.Offset = &offset
	return aecq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (aecq *AuthorizationEndpointConfigQuery) Unique(unique bool) *AuthorizationEndpointConfigQuery {
	aecq.ctx.Unique = &unique
	return aecq
}

// Order specifies how the records should be ordered.
func (aecq *AuthorizationEndpointConfigQuery) Order(o ...authorizationendpointconfig.OrderOption) *AuthorizationEndpointConfigQuery {
	aecq.order = append(aecq.order, o...)
	return aecq
}

// QueryService chains the current query on the "service" edge.
func (aecq *AuthorizationEndpointConfigQuery) QueryService() *ServiceQuery {
	query := (&ServiceClient{config: aecq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := aecq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := aecq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(authorizationendpointconfig.Table, authorizationendpointconfig.FieldID, selector),
			sqlgraph.To(service.Table, service.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, authorizationendpointconfig.ServiceTable, authorizationendpointconfig.ServiceColumn),
		)
		fromU = sqlgraph.SetNeighbors(aecq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first AuthorizationEndpointConfig entity from the query.
// Returns a *NotFoundError when no AuthorizationEndpointConfig was found.
func (aecq *AuthorizationEndpointConfigQuery) First(ctx context.Context) (*AuthorizationEndpointConfig, error) {
	nodes, err := aecq.Limit(1).All(setContextOp(ctx, aecq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{authorizationendpointconfig.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (aecq *AuthorizationEndpointConfigQuery) FirstX(ctx context.Context) *AuthorizationEndpointConfig {
	node, err := aecq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first AuthorizationEndpointConfig ID from the query.
// Returns a *NotFoundError when no AuthorizationEndpointConfig ID was found.
func (aecq *AuthorizationEndpointConfigQuery) FirstID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = aecq.Limit(1).IDs(setContextOp(ctx, aecq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{authorizationendpointconfig.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (aecq *AuthorizationEndpointConfigQuery) FirstIDX(ctx context.Context) string {
	id, err := aecq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single AuthorizationEndpointConfig entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one AuthorizationEndpointConfig entity is found.
// Returns a *NotFoundError when no AuthorizationEndpointConfig entities are found.
func (aecq *AuthorizationEndpointConfigQuery) Only(ctx context.Context) (*AuthorizationEndpointConfig, error) {
	nodes, err := aecq.Limit(2).All(setContextOp(ctx, aecq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{authorizationendpointconfig.Label}
	default:
		return nil, &NotSingularError{authorizationendpointconfig.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (aecq *AuthorizationEndpointConfigQuery) OnlyX(ctx context.Context) *AuthorizationEndpointConfig {
	node, err := aecq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only AuthorizationEndpointConfig ID in the query.
// Returns a *NotSingularError when more than one AuthorizationEndpointConfig ID is found.
// Returns a *NotFoundError when no entities are found.
func (aecq *AuthorizationEndpointConfigQuery) OnlyID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = aecq.Limit(2).IDs(setContextOp(ctx, aecq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{authorizationendpointconfig.Label}
	default:
		err = &NotSingularError{authorizationendpointconfig.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (aecq *AuthorizationEndpointConfigQuery) OnlyIDX(ctx context.Context) string {
	id, err := aecq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of AuthorizationEndpointConfigs.
func (aecq *AuthorizationEndpointConfigQuery) All(ctx context.Context) ([]*AuthorizationEndpointConfig, error) {
	ctx = setContextOp(ctx, aecq.ctx, "All")
	if err := aecq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*AuthorizationEndpointConfig, *AuthorizationEndpointConfigQuery]()
	return withInterceptors[[]*AuthorizationEndpointConfig](ctx, aecq, qr, aecq.inters)
}

// AllX is like All, but panics if an error occurs.
func (aecq *AuthorizationEndpointConfigQuery) AllX(ctx context.Context) []*AuthorizationEndpointConfig {
	nodes, err := aecq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of AuthorizationEndpointConfig IDs.
func (aecq *AuthorizationEndpointConfigQuery) IDs(ctx context.Context) (ids []string, err error) {
	if aecq.ctx.Unique == nil && aecq.path != nil {
		aecq.Unique(true)
	}
	ctx = setContextOp(ctx, aecq.ctx, "IDs")
	if err = aecq.Select(authorizationendpointconfig.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (aecq *AuthorizationEndpointConfigQuery) IDsX(ctx context.Context) []string {
	ids, err := aecq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (aecq *AuthorizationEndpointConfigQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, aecq.ctx, "Count")
	if err := aecq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, aecq, querierCount[*AuthorizationEndpointConfigQuery](), aecq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (aecq *AuthorizationEndpointConfigQuery) CountX(ctx context.Context) int {
	count, err := aecq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (aecq *AuthorizationEndpointConfigQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, aecq.ctx, "Exist")
	switch _, err := aecq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (aecq *AuthorizationEndpointConfigQuery) ExistX(ctx context.Context) bool {
	exist, err := aecq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the AuthorizationEndpointConfigQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (aecq *AuthorizationEndpointConfigQuery) Clone() *AuthorizationEndpointConfigQuery {
	if aecq == nil {
		return nil
	}
	return &AuthorizationEndpointConfigQuery{
		config:      aecq.config,
		ctx:         aecq.ctx.Clone(),
		order:       append([]authorizationendpointconfig.OrderOption{}, aecq.order...),
		inters:      append([]Interceptor{}, aecq.inters...),
		predicates:  append([]predicate.AuthorizationEndpointConfig{}, aecq.predicates...),
		withService: aecq.withService.Clone(),
		// clone intermediate query.
		sql:  aecq.sql.Clone(),
		path: aecq.path,
	}
}

// WithService tells the query-builder to eager-load the nodes that are connected to
// the "service" edge. The optional arguments are used to configure the query builder of the edge.
func (aecq *AuthorizationEndpointConfigQuery) WithService(opts ...func(*ServiceQuery)) *AuthorizationEndpointConfigQuery {
	query := (&ServiceClient{config: aecq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	aecq.withService = query
	return aecq
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
//	client.AuthorizationEndpointConfig.Query().
//		GroupBy(authorizationendpointconfig.FieldEndpoint).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (aecq *AuthorizationEndpointConfigQuery) GroupBy(field string, fields ...string) *AuthorizationEndpointConfigGroupBy {
	aecq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &AuthorizationEndpointConfigGroupBy{build: aecq}
	grbuild.flds = &aecq.ctx.Fields
	grbuild.label = authorizationendpointconfig.Label
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
//	client.AuthorizationEndpointConfig.Query().
//		Select(authorizationendpointconfig.FieldEndpoint).
//		Scan(ctx, &v)
func (aecq *AuthorizationEndpointConfigQuery) Select(fields ...string) *AuthorizationEndpointConfigSelect {
	aecq.ctx.Fields = append(aecq.ctx.Fields, fields...)
	sbuild := &AuthorizationEndpointConfigSelect{AuthorizationEndpointConfigQuery: aecq}
	sbuild.label = authorizationendpointconfig.Label
	sbuild.flds, sbuild.scan = &aecq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a AuthorizationEndpointConfigSelect configured with the given aggregations.
func (aecq *AuthorizationEndpointConfigQuery) Aggregate(fns ...AggregateFunc) *AuthorizationEndpointConfigSelect {
	return aecq.Select().Aggregate(fns...)
}

func (aecq *AuthorizationEndpointConfigQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range aecq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, aecq); err != nil {
				return err
			}
		}
	}
	for _, f := range aecq.ctx.Fields {
		if !authorizationendpointconfig.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if aecq.path != nil {
		prev, err := aecq.path(ctx)
		if err != nil {
			return err
		}
		aecq.sql = prev
	}
	return nil
}

func (aecq *AuthorizationEndpointConfigQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*AuthorizationEndpointConfig, error) {
	var (
		nodes       = []*AuthorizationEndpointConfig{}
		withFKs     = aecq.withFKs
		_spec       = aecq.querySpec()
		loadedTypes = [1]bool{
			aecq.withService != nil,
		}
	)
	if aecq.withService != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, authorizationendpointconfig.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*AuthorizationEndpointConfig).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &AuthorizationEndpointConfig{config: aecq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, aecq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := aecq.withService; query != nil {
		if err := aecq.loadService(ctx, query, nodes, nil,
			func(n *AuthorizationEndpointConfig, e *Service) { n.Edges.Service = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (aecq *AuthorizationEndpointConfigQuery) loadService(ctx context.Context, query *ServiceQuery, nodes []*AuthorizationEndpointConfig, init func(*AuthorizationEndpointConfig), assign func(*AuthorizationEndpointConfig, *Service)) error {
	ids := make([]string, 0, len(nodes))
	nodeids := make(map[string][]*AuthorizationEndpointConfig)
	for i := range nodes {
		if nodes[i].service_service_authorization_endpoint_config == nil {
			continue
		}
		fk := *nodes[i].service_service_authorization_endpoint_config
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
			return fmt.Errorf(`unexpected foreign-key "service_service_authorization_endpoint_config" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (aecq *AuthorizationEndpointConfigQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := aecq.querySpec()
	_spec.Node.Columns = aecq.ctx.Fields
	if len(aecq.ctx.Fields) > 0 {
		_spec.Unique = aecq.ctx.Unique != nil && *aecq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, aecq.driver, _spec)
}

func (aecq *AuthorizationEndpointConfigQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(authorizationendpointconfig.Table, authorizationendpointconfig.Columns, sqlgraph.NewFieldSpec(authorizationendpointconfig.FieldID, field.TypeString))
	_spec.From = aecq.sql
	if unique := aecq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if aecq.path != nil {
		_spec.Unique = true
	}
	if fields := aecq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, authorizationendpointconfig.FieldID)
		for i := range fields {
			if fields[i] != authorizationendpointconfig.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := aecq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := aecq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := aecq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := aecq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (aecq *AuthorizationEndpointConfigQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(aecq.driver.Dialect())
	t1 := builder.Table(authorizationendpointconfig.Table)
	columns := aecq.ctx.Fields
	if len(columns) == 0 {
		columns = authorizationendpointconfig.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if aecq.sql != nil {
		selector = aecq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if aecq.ctx.Unique != nil && *aecq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range aecq.predicates {
		p(selector)
	}
	for _, p := range aecq.order {
		p(selector)
	}
	if offset := aecq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := aecq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// AuthorizationEndpointConfigGroupBy is the group-by builder for AuthorizationEndpointConfig entities.
type AuthorizationEndpointConfigGroupBy struct {
	selector
	build *AuthorizationEndpointConfigQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (aecgb *AuthorizationEndpointConfigGroupBy) Aggregate(fns ...AggregateFunc) *AuthorizationEndpointConfigGroupBy {
	aecgb.fns = append(aecgb.fns, fns...)
	return aecgb
}

// Scan applies the selector query and scans the result into the given value.
func (aecgb *AuthorizationEndpointConfigGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, aecgb.build.ctx, "GroupBy")
	if err := aecgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*AuthorizationEndpointConfigQuery, *AuthorizationEndpointConfigGroupBy](ctx, aecgb.build, aecgb, aecgb.build.inters, v)
}

func (aecgb *AuthorizationEndpointConfigGroupBy) sqlScan(ctx context.Context, root *AuthorizationEndpointConfigQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(aecgb.fns))
	for _, fn := range aecgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*aecgb.flds)+len(aecgb.fns))
		for _, f := range *aecgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*aecgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := aecgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// AuthorizationEndpointConfigSelect is the builder for selecting fields of AuthorizationEndpointConfig entities.
type AuthorizationEndpointConfigSelect struct {
	*AuthorizationEndpointConfigQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (aecs *AuthorizationEndpointConfigSelect) Aggregate(fns ...AggregateFunc) *AuthorizationEndpointConfigSelect {
	aecs.fns = append(aecs.fns, fns...)
	return aecs
}

// Scan applies the selector query and scans the result into the given value.
func (aecs *AuthorizationEndpointConfigSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, aecs.ctx, "Select")
	if err := aecs.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*AuthorizationEndpointConfigQuery, *AuthorizationEndpointConfigSelect](ctx, aecs.AuthorizationEndpointConfigQuery, aecs, aecs.inters, v)
}

func (aecs *AuthorizationEndpointConfigSelect) sqlScan(ctx context.Context, root *AuthorizationEndpointConfigQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(aecs.fns))
	for _, fn := range aecs.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*aecs.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := aecs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
