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
	"go.authbricks.com/bricks/ent/keyset"
	"go.authbricks.com/bricks/ent/oauthclient"
	"go.authbricks.com/bricks/ent/oauthserver"
	"go.authbricks.com/bricks/ent/predicate"
)

// OAuthServerQuery is the builder for querying OAuthServer entities.
type OAuthServerQuery struct {
	config
	ctx         *QueryContext
	order       []oauthserver.OrderOption
	inters      []Interceptor
	predicates  []predicate.OAuthServer
	withKeySet  *KeySetQuery
	withClients *OAuthClientQuery
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the OAuthServerQuery builder.
func (osq *OAuthServerQuery) Where(ps ...predicate.OAuthServer) *OAuthServerQuery {
	osq.predicates = append(osq.predicates, ps...)
	return osq
}

// Limit the number of records to be returned by this query.
func (osq *OAuthServerQuery) Limit(limit int) *OAuthServerQuery {
	osq.ctx.Limit = &limit
	return osq
}

// Offset to start from.
func (osq *OAuthServerQuery) Offset(offset int) *OAuthServerQuery {
	osq.ctx.Offset = &offset
	return osq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (osq *OAuthServerQuery) Unique(unique bool) *OAuthServerQuery {
	osq.ctx.Unique = &unique
	return osq
}

// Order specifies how the records should be ordered.
func (osq *OAuthServerQuery) Order(o ...oauthserver.OrderOption) *OAuthServerQuery {
	osq.order = append(osq.order, o...)
	return osq
}

// QueryKeySet chains the current query on the "key_set" edge.
func (osq *OAuthServerQuery) QueryKeySet() *KeySetQuery {
	query := (&KeySetClient{config: osq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := osq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := osq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(oauthserver.Table, oauthserver.FieldID, selector),
			sqlgraph.To(keyset.Table, keyset.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, false, oauthserver.KeySetTable, oauthserver.KeySetColumn),
		)
		fromU = sqlgraph.SetNeighbors(osq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryClients chains the current query on the "clients" edge.
func (osq *OAuthServerQuery) QueryClients() *OAuthClientQuery {
	query := (&OAuthClientClient{config: osq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := osq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := osq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(oauthserver.Table, oauthserver.FieldID, selector),
			sqlgraph.To(oauthclient.Table, oauthclient.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, oauthserver.ClientsTable, oauthserver.ClientsColumn),
		)
		fromU = sqlgraph.SetNeighbors(osq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first OAuthServer entity from the query.
// Returns a *NotFoundError when no OAuthServer was found.
func (osq *OAuthServerQuery) First(ctx context.Context) (*OAuthServer, error) {
	nodes, err := osq.Limit(1).All(setContextOp(ctx, osq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{oauthserver.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (osq *OAuthServerQuery) FirstX(ctx context.Context) *OAuthServer {
	node, err := osq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first OAuthServer ID from the query.
// Returns a *NotFoundError when no OAuthServer ID was found.
func (osq *OAuthServerQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = osq.Limit(1).IDs(setContextOp(ctx, osq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{oauthserver.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (osq *OAuthServerQuery) FirstIDX(ctx context.Context) int {
	id, err := osq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single OAuthServer entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one OAuthServer entity is found.
// Returns a *NotFoundError when no OAuthServer entities are found.
func (osq *OAuthServerQuery) Only(ctx context.Context) (*OAuthServer, error) {
	nodes, err := osq.Limit(2).All(setContextOp(ctx, osq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{oauthserver.Label}
	default:
		return nil, &NotSingularError{oauthserver.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (osq *OAuthServerQuery) OnlyX(ctx context.Context) *OAuthServer {
	node, err := osq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only OAuthServer ID in the query.
// Returns a *NotSingularError when more than one OAuthServer ID is found.
// Returns a *NotFoundError when no entities are found.
func (osq *OAuthServerQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = osq.Limit(2).IDs(setContextOp(ctx, osq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{oauthserver.Label}
	default:
		err = &NotSingularError{oauthserver.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (osq *OAuthServerQuery) OnlyIDX(ctx context.Context) int {
	id, err := osq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of OAuthServers.
func (osq *OAuthServerQuery) All(ctx context.Context) ([]*OAuthServer, error) {
	ctx = setContextOp(ctx, osq.ctx, "All")
	if err := osq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*OAuthServer, *OAuthServerQuery]()
	return withInterceptors[[]*OAuthServer](ctx, osq, qr, osq.inters)
}

// AllX is like All, but panics if an error occurs.
func (osq *OAuthServerQuery) AllX(ctx context.Context) []*OAuthServer {
	nodes, err := osq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of OAuthServer IDs.
func (osq *OAuthServerQuery) IDs(ctx context.Context) (ids []int, err error) {
	if osq.ctx.Unique == nil && osq.path != nil {
		osq.Unique(true)
	}
	ctx = setContextOp(ctx, osq.ctx, "IDs")
	if err = osq.Select(oauthserver.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (osq *OAuthServerQuery) IDsX(ctx context.Context) []int {
	ids, err := osq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (osq *OAuthServerQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, osq.ctx, "Count")
	if err := osq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, osq, querierCount[*OAuthServerQuery](), osq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (osq *OAuthServerQuery) CountX(ctx context.Context) int {
	count, err := osq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (osq *OAuthServerQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, osq.ctx, "Exist")
	switch _, err := osq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (osq *OAuthServerQuery) ExistX(ctx context.Context) bool {
	exist, err := osq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the OAuthServerQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (osq *OAuthServerQuery) Clone() *OAuthServerQuery {
	if osq == nil {
		return nil
	}
	return &OAuthServerQuery{
		config:      osq.config,
		ctx:         osq.ctx.Clone(),
		order:       append([]oauthserver.OrderOption{}, osq.order...),
		inters:      append([]Interceptor{}, osq.inters...),
		predicates:  append([]predicate.OAuthServer{}, osq.predicates...),
		withKeySet:  osq.withKeySet.Clone(),
		withClients: osq.withClients.Clone(),
		// clone intermediate query.
		sql:  osq.sql.Clone(),
		path: osq.path,
	}
}

// WithKeySet tells the query-builder to eager-load the nodes that are connected to
// the "key_set" edge. The optional arguments are used to configure the query builder of the edge.
func (osq *OAuthServerQuery) WithKeySet(opts ...func(*KeySetQuery)) *OAuthServerQuery {
	query := (&KeySetClient{config: osq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	osq.withKeySet = query
	return osq
}

// WithClients tells the query-builder to eager-load the nodes that are connected to
// the "clients" edge. The optional arguments are used to configure the query builder of the edge.
func (osq *OAuthServerQuery) WithClients(opts ...func(*OAuthClientQuery)) *OAuthServerQuery {
	query := (&OAuthClientClient{config: osq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	osq.withClients = query
	return osq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
func (osq *OAuthServerQuery) GroupBy(field string, fields ...string) *OAuthServerGroupBy {
	osq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &OAuthServerGroupBy{build: osq}
	grbuild.flds = &osq.ctx.Fields
	grbuild.label = oauthserver.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
func (osq *OAuthServerQuery) Select(fields ...string) *OAuthServerSelect {
	osq.ctx.Fields = append(osq.ctx.Fields, fields...)
	sbuild := &OAuthServerSelect{OAuthServerQuery: osq}
	sbuild.label = oauthserver.Label
	sbuild.flds, sbuild.scan = &osq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a OAuthServerSelect configured with the given aggregations.
func (osq *OAuthServerQuery) Aggregate(fns ...AggregateFunc) *OAuthServerSelect {
	return osq.Select().Aggregate(fns...)
}

func (osq *OAuthServerQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range osq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, osq); err != nil {
				return err
			}
		}
	}
	for _, f := range osq.ctx.Fields {
		if !oauthserver.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if osq.path != nil {
		prev, err := osq.path(ctx)
		if err != nil {
			return err
		}
		osq.sql = prev
	}
	return nil
}

func (osq *OAuthServerQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*OAuthServer, error) {
	var (
		nodes       = []*OAuthServer{}
		_spec       = osq.querySpec()
		loadedTypes = [2]bool{
			osq.withKeySet != nil,
			osq.withClients != nil,
		}
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*OAuthServer).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &OAuthServer{config: osq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, osq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := osq.withKeySet; query != nil {
		if err := osq.loadKeySet(ctx, query, nodes, nil,
			func(n *OAuthServer, e *KeySet) { n.Edges.KeySet = e }); err != nil {
			return nil, err
		}
	}
	if query := osq.withClients; query != nil {
		if err := osq.loadClients(ctx, query, nodes,
			func(n *OAuthServer) { n.Edges.Clients = []*OAuthClient{} },
			func(n *OAuthServer, e *OAuthClient) { n.Edges.Clients = append(n.Edges.Clients, e) }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (osq *OAuthServerQuery) loadKeySet(ctx context.Context, query *KeySetQuery, nodes []*OAuthServer, init func(*OAuthServer), assign func(*OAuthServer, *KeySet)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[int]*OAuthServer)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
	}
	query.withFKs = true
	query.Where(predicate.KeySet(func(s *sql.Selector) {
		s.Where(sql.InValues(s.C(oauthserver.KeySetColumn), fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.oauth_server_key_set
		if fk == nil {
			return fmt.Errorf(`foreign-key "oauth_server_key_set" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected referenced foreign-key "oauth_server_key_set" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}
func (osq *OAuthServerQuery) loadClients(ctx context.Context, query *OAuthClientQuery, nodes []*OAuthServer, init func(*OAuthServer), assign func(*OAuthServer, *OAuthClient)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[int]*OAuthServer)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
		if init != nil {
			init(nodes[i])
		}
	}
	query.withFKs = true
	query.Where(predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.InValues(s.C(oauthserver.ClientsColumn), fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.oauth_server_clients
		if fk == nil {
			return fmt.Errorf(`foreign-key "oauth_server_clients" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected referenced foreign-key "oauth_server_clients" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}

func (osq *OAuthServerQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := osq.querySpec()
	_spec.Node.Columns = osq.ctx.Fields
	if len(osq.ctx.Fields) > 0 {
		_spec.Unique = osq.ctx.Unique != nil && *osq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, osq.driver, _spec)
}

func (osq *OAuthServerQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(oauthserver.Table, oauthserver.Columns, sqlgraph.NewFieldSpec(oauthserver.FieldID, field.TypeInt))
	_spec.From = osq.sql
	if unique := osq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if osq.path != nil {
		_spec.Unique = true
	}
	if fields := osq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, oauthserver.FieldID)
		for i := range fields {
			if fields[i] != oauthserver.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := osq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := osq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := osq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := osq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (osq *OAuthServerQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(osq.driver.Dialect())
	t1 := builder.Table(oauthserver.Table)
	columns := osq.ctx.Fields
	if len(columns) == 0 {
		columns = oauthserver.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if osq.sql != nil {
		selector = osq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if osq.ctx.Unique != nil && *osq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range osq.predicates {
		p(selector)
	}
	for _, p := range osq.order {
		p(selector)
	}
	if offset := osq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := osq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// OAuthServerGroupBy is the group-by builder for OAuthServer entities.
type OAuthServerGroupBy struct {
	selector
	build *OAuthServerQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (osgb *OAuthServerGroupBy) Aggregate(fns ...AggregateFunc) *OAuthServerGroupBy {
	osgb.fns = append(osgb.fns, fns...)
	return osgb
}

// Scan applies the selector query and scans the result into the given value.
func (osgb *OAuthServerGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, osgb.build.ctx, "GroupBy")
	if err := osgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*OAuthServerQuery, *OAuthServerGroupBy](ctx, osgb.build, osgb, osgb.build.inters, v)
}

func (osgb *OAuthServerGroupBy) sqlScan(ctx context.Context, root *OAuthServerQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(osgb.fns))
	for _, fn := range osgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*osgb.flds)+len(osgb.fns))
		for _, f := range *osgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*osgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := osgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// OAuthServerSelect is the builder for selecting fields of OAuthServer entities.
type OAuthServerSelect struct {
	*OAuthServerQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (oss *OAuthServerSelect) Aggregate(fns ...AggregateFunc) *OAuthServerSelect {
	oss.fns = append(oss.fns, fns...)
	return oss
}

// Scan applies the selector query and scans the result into the given value.
func (oss *OAuthServerSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, oss.ctx, "Select")
	if err := oss.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*OAuthServerQuery, *OAuthServerSelect](ctx, oss.OAuthServerQuery, oss, oss.inters, v)
}

func (oss *OAuthServerSelect) sqlScan(ctx context.Context, root *OAuthServerQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(oss.fns))
	for _, fn := range oss.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*oss.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := oss.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}