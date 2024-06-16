// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"database/sql/driver"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/application"
	"go.authbricks.com/bricks/ent/predicate"
	"go.authbricks.com/bricks/ent/service"
	"go.authbricks.com/bricks/ent/serviceconfig"
)

// ServiceQuery is the builder for querying Service entities.
type ServiceQuery struct {
	config
	ctx               *QueryContext
	order             []service.OrderOption
	inters            []Interceptor
	predicates        []predicate.Service
	withServiceConfig *ServiceConfigQuery
	withApplications  *ApplicationQuery
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the ServiceQuery builder.
func (sq *ServiceQuery) Where(ps ...predicate.Service) *ServiceQuery {
	sq.predicates = append(sq.predicates, ps...)
	return sq
}

// Limit the number of records to be returned by this query.
func (sq *ServiceQuery) Limit(limit int) *ServiceQuery {
	sq.ctx.Limit = &limit
	return sq
}

// Offset to start from.
func (sq *ServiceQuery) Offset(offset int) *ServiceQuery {
	sq.ctx.Offset = &offset
	return sq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (sq *ServiceQuery) Unique(unique bool) *ServiceQuery {
	sq.ctx.Unique = &unique
	return sq
}

// Order specifies how the records should be ordered.
func (sq *ServiceQuery) Order(o ...service.OrderOption) *ServiceQuery {
	sq.order = append(sq.order, o...)
	return sq
}

// QueryServiceConfig chains the current query on the "service_config" edge.
func (sq *ServiceQuery) QueryServiceConfig() *ServiceConfigQuery {
	query := (&ServiceConfigClient{config: sq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := sq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := sq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(service.Table, service.FieldID, selector),
			sqlgraph.To(serviceconfig.Table, serviceconfig.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, false, service.ServiceConfigTable, service.ServiceConfigColumn),
		)
		fromU = sqlgraph.SetNeighbors(sq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryApplications chains the current query on the "applications" edge.
func (sq *ServiceQuery) QueryApplications() *ApplicationQuery {
	query := (&ApplicationClient{config: sq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := sq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := sq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(service.Table, service.FieldID, selector),
			sqlgraph.To(application.Table, application.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, service.ApplicationsTable, service.ApplicationsColumn),
		)
		fromU = sqlgraph.SetNeighbors(sq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first Service entity from the query.
// Returns a *NotFoundError when no Service was found.
func (sq *ServiceQuery) First(ctx context.Context) (*Service, error) {
	nodes, err := sq.Limit(1).All(setContextOp(ctx, sq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{service.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (sq *ServiceQuery) FirstX(ctx context.Context) *Service {
	node, err := sq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first Service ID from the query.
// Returns a *NotFoundError when no Service ID was found.
func (sq *ServiceQuery) FirstID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = sq.Limit(1).IDs(setContextOp(ctx, sq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{service.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (sq *ServiceQuery) FirstIDX(ctx context.Context) string {
	id, err := sq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single Service entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one Service entity is found.
// Returns a *NotFoundError when no Service entities are found.
func (sq *ServiceQuery) Only(ctx context.Context) (*Service, error) {
	nodes, err := sq.Limit(2).All(setContextOp(ctx, sq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{service.Label}
	default:
		return nil, &NotSingularError{service.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (sq *ServiceQuery) OnlyX(ctx context.Context) *Service {
	node, err := sq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only Service ID in the query.
// Returns a *NotSingularError when more than one Service ID is found.
// Returns a *NotFoundError when no entities are found.
func (sq *ServiceQuery) OnlyID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = sq.Limit(2).IDs(setContextOp(ctx, sq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{service.Label}
	default:
		err = &NotSingularError{service.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (sq *ServiceQuery) OnlyIDX(ctx context.Context) string {
	id, err := sq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of Services.
func (sq *ServiceQuery) All(ctx context.Context) ([]*Service, error) {
	ctx = setContextOp(ctx, sq.ctx, "All")
	if err := sq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*Service, *ServiceQuery]()
	return withInterceptors[[]*Service](ctx, sq, qr, sq.inters)
}

// AllX is like All, but panics if an error occurs.
func (sq *ServiceQuery) AllX(ctx context.Context) []*Service {
	nodes, err := sq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of Service IDs.
func (sq *ServiceQuery) IDs(ctx context.Context) (ids []string, err error) {
	if sq.ctx.Unique == nil && sq.path != nil {
		sq.Unique(true)
	}
	ctx = setContextOp(ctx, sq.ctx, "IDs")
	if err = sq.Select(service.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (sq *ServiceQuery) IDsX(ctx context.Context) []string {
	ids, err := sq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (sq *ServiceQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, sq.ctx, "Count")
	if err := sq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, sq, querierCount[*ServiceQuery](), sq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (sq *ServiceQuery) CountX(ctx context.Context) int {
	count, err := sq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (sq *ServiceQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, sq.ctx, "Exist")
	switch _, err := sq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (sq *ServiceQuery) ExistX(ctx context.Context) bool {
	exist, err := sq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the ServiceQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (sq *ServiceQuery) Clone() *ServiceQuery {
	if sq == nil {
		return nil
	}
	return &ServiceQuery{
		config:            sq.config,
		ctx:               sq.ctx.Clone(),
		order:             append([]service.OrderOption{}, sq.order...),
		inters:            append([]Interceptor{}, sq.inters...),
		predicates:        append([]predicate.Service{}, sq.predicates...),
		withServiceConfig: sq.withServiceConfig.Clone(),
		withApplications:  sq.withApplications.Clone(),
		// clone intermediate query.
		sql:  sq.sql.Clone(),
		path: sq.path,
	}
}

// WithServiceConfig tells the query-builder to eager-load the nodes that are connected to
// the "service_config" edge. The optional arguments are used to configure the query builder of the edge.
func (sq *ServiceQuery) WithServiceConfig(opts ...func(*ServiceConfigQuery)) *ServiceQuery {
	query := (&ServiceConfigClient{config: sq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	sq.withServiceConfig = query
	return sq
}

// WithApplications tells the query-builder to eager-load the nodes that are connected to
// the "applications" edge. The optional arguments are used to configure the query builder of the edge.
func (sq *ServiceQuery) WithApplications(opts ...func(*ApplicationQuery)) *ServiceQuery {
	query := (&ApplicationClient{config: sq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	sq.withApplications = query
	return sq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		Name string `json:"name" hcl:"name"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.Service.Query().
//		GroupBy(service.FieldName).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (sq *ServiceQuery) GroupBy(field string, fields ...string) *ServiceGroupBy {
	sq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &ServiceGroupBy{build: sq}
	grbuild.flds = &sq.ctx.Fields
	grbuild.label = service.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		Name string `json:"name" hcl:"name"`
//	}
//
//	client.Service.Query().
//		Select(service.FieldName).
//		Scan(ctx, &v)
func (sq *ServiceQuery) Select(fields ...string) *ServiceSelect {
	sq.ctx.Fields = append(sq.ctx.Fields, fields...)
	sbuild := &ServiceSelect{ServiceQuery: sq}
	sbuild.label = service.Label
	sbuild.flds, sbuild.scan = &sq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a ServiceSelect configured with the given aggregations.
func (sq *ServiceQuery) Aggregate(fns ...AggregateFunc) *ServiceSelect {
	return sq.Select().Aggregate(fns...)
}

func (sq *ServiceQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range sq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, sq); err != nil {
				return err
			}
		}
	}
	for _, f := range sq.ctx.Fields {
		if !service.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if sq.path != nil {
		prev, err := sq.path(ctx)
		if err != nil {
			return err
		}
		sq.sql = prev
	}
	return nil
}

func (sq *ServiceQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*Service, error) {
	var (
		nodes       = []*Service{}
		_spec       = sq.querySpec()
		loadedTypes = [2]bool{
			sq.withServiceConfig != nil,
			sq.withApplications != nil,
		}
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*Service).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &Service{config: sq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, sq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := sq.withServiceConfig; query != nil {
		if err := sq.loadServiceConfig(ctx, query, nodes, nil,
			func(n *Service, e *ServiceConfig) { n.Edges.ServiceConfig = e }); err != nil {
			return nil, err
		}
	}
	if query := sq.withApplications; query != nil {
		if err := sq.loadApplications(ctx, query, nodes,
			func(n *Service) { n.Edges.Applications = []*Application{} },
			func(n *Service, e *Application) { n.Edges.Applications = append(n.Edges.Applications, e) }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (sq *ServiceQuery) loadServiceConfig(ctx context.Context, query *ServiceConfigQuery, nodes []*Service, init func(*Service), assign func(*Service, *ServiceConfig)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[string]*Service)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
	}
	query.withFKs = true
	query.Where(predicate.ServiceConfig(func(s *sql.Selector) {
		s.Where(sql.InValues(s.C(service.ServiceConfigColumn), fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.service_service_config
		if fk == nil {
			return fmt.Errorf(`foreign-key "service_service_config" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected referenced foreign-key "service_service_config" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}
func (sq *ServiceQuery) loadApplications(ctx context.Context, query *ApplicationQuery, nodes []*Service, init func(*Service), assign func(*Service, *Application)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[string]*Service)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
		if init != nil {
			init(nodes[i])
		}
	}
	query.withFKs = true
	query.Where(predicate.Application(func(s *sql.Selector) {
		s.Where(sql.InValues(s.C(service.ApplicationsColumn), fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.service_applications
		if fk == nil {
			return fmt.Errorf(`foreign-key "service_applications" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected referenced foreign-key "service_applications" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}

func (sq *ServiceQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := sq.querySpec()
	_spec.Node.Columns = sq.ctx.Fields
	if len(sq.ctx.Fields) > 0 {
		_spec.Unique = sq.ctx.Unique != nil && *sq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, sq.driver, _spec)
}

func (sq *ServiceQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(service.Table, service.Columns, sqlgraph.NewFieldSpec(service.FieldID, field.TypeString))
	_spec.From = sq.sql
	if unique := sq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if sq.path != nil {
		_spec.Unique = true
	}
	if fields := sq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, service.FieldID)
		for i := range fields {
			if fields[i] != service.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := sq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := sq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := sq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := sq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (sq *ServiceQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(sq.driver.Dialect())
	t1 := builder.Table(service.Table)
	columns := sq.ctx.Fields
	if len(columns) == 0 {
		columns = service.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if sq.sql != nil {
		selector = sq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if sq.ctx.Unique != nil && *sq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range sq.predicates {
		p(selector)
	}
	for _, p := range sq.order {
		p(selector)
	}
	if offset := sq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := sq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// ServiceGroupBy is the group-by builder for Service entities.
type ServiceGroupBy struct {
	selector
	build *ServiceQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (sgb *ServiceGroupBy) Aggregate(fns ...AggregateFunc) *ServiceGroupBy {
	sgb.fns = append(sgb.fns, fns...)
	return sgb
}

// Scan applies the selector query and scans the result into the given value.
func (sgb *ServiceGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, sgb.build.ctx, "GroupBy")
	if err := sgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*ServiceQuery, *ServiceGroupBy](ctx, sgb.build, sgb, sgb.build.inters, v)
}

func (sgb *ServiceGroupBy) sqlScan(ctx context.Context, root *ServiceQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(sgb.fns))
	for _, fn := range sgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*sgb.flds)+len(sgb.fns))
		for _, f := range *sgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*sgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := sgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// ServiceSelect is the builder for selecting fields of Service entities.
type ServiceSelect struct {
	*ServiceQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (ss *ServiceSelect) Aggregate(fns ...AggregateFunc) *ServiceSelect {
	ss.fns = append(ss.fns, fns...)
	return ss
}

// Scan applies the selector query and scans the result into the given value.
func (ss *ServiceSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, ss.ctx, "Select")
	if err := ss.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*ServiceQuery, *ServiceSelect](ctx, ss.ServiceQuery, ss, ss.inters, v)
}

func (ss *ServiceSelect) sqlScan(ctx context.Context, root *ServiceQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(ss.fns))
	for _, fn := range ss.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*ss.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := ss.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}