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
	"go.authbricks.com/bricks/ent/connectionconfig"
	"go.authbricks.com/bricks/ent/oidcconnection"
	"go.authbricks.com/bricks/ent/predicate"
	"go.authbricks.com/bricks/ent/user"
)

// OIDCConnectionQuery is the builder for querying OIDCConnection entities.
type OIDCConnectionQuery struct {
	config
	ctx                  *QueryContext
	order                []oidcconnection.OrderOption
	inters               []Interceptor
	predicates           []predicate.OIDCConnection
	withConnectionConfig *ConnectionConfigQuery
	withUsers            *UserQuery
	withFKs              bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the OIDCConnectionQuery builder.
func (ocq *OIDCConnectionQuery) Where(ps ...predicate.OIDCConnection) *OIDCConnectionQuery {
	ocq.predicates = append(ocq.predicates, ps...)
	return ocq
}

// Limit the number of records to be returned by this query.
func (ocq *OIDCConnectionQuery) Limit(limit int) *OIDCConnectionQuery {
	ocq.ctx.Limit = &limit
	return ocq
}

// Offset to start from.
func (ocq *OIDCConnectionQuery) Offset(offset int) *OIDCConnectionQuery {
	ocq.ctx.Offset = &offset
	return ocq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (ocq *OIDCConnectionQuery) Unique(unique bool) *OIDCConnectionQuery {
	ocq.ctx.Unique = &unique
	return ocq
}

// Order specifies how the records should be ordered.
func (ocq *OIDCConnectionQuery) Order(o ...oidcconnection.OrderOption) *OIDCConnectionQuery {
	ocq.order = append(ocq.order, o...)
	return ocq
}

// QueryConnectionConfig chains the current query on the "connection_config" edge.
func (ocq *OIDCConnectionQuery) QueryConnectionConfig() *ConnectionConfigQuery {
	query := (&ConnectionConfigClient{config: ocq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := ocq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := ocq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(oidcconnection.Table, oidcconnection.FieldID, selector),
			sqlgraph.To(connectionconfig.Table, connectionconfig.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, oidcconnection.ConnectionConfigTable, oidcconnection.ConnectionConfigColumn),
		)
		fromU = sqlgraph.SetNeighbors(ocq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryUsers chains the current query on the "users" edge.
func (ocq *OIDCConnectionQuery) QueryUsers() *UserQuery {
	query := (&UserClient{config: ocq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := ocq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := ocq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(oidcconnection.Table, oidcconnection.FieldID, selector),
			sqlgraph.To(user.Table, user.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, false, oidcconnection.UsersTable, oidcconnection.UsersColumn),
		)
		fromU = sqlgraph.SetNeighbors(ocq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first OIDCConnection entity from the query.
// Returns a *NotFoundError when no OIDCConnection was found.
func (ocq *OIDCConnectionQuery) First(ctx context.Context) (*OIDCConnection, error) {
	nodes, err := ocq.Limit(1).All(setContextOp(ctx, ocq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{oidcconnection.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (ocq *OIDCConnectionQuery) FirstX(ctx context.Context) *OIDCConnection {
	node, err := ocq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first OIDCConnection ID from the query.
// Returns a *NotFoundError when no OIDCConnection ID was found.
func (ocq *OIDCConnectionQuery) FirstID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = ocq.Limit(1).IDs(setContextOp(ctx, ocq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{oidcconnection.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (ocq *OIDCConnectionQuery) FirstIDX(ctx context.Context) string {
	id, err := ocq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single OIDCConnection entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one OIDCConnection entity is found.
// Returns a *NotFoundError when no OIDCConnection entities are found.
func (ocq *OIDCConnectionQuery) Only(ctx context.Context) (*OIDCConnection, error) {
	nodes, err := ocq.Limit(2).All(setContextOp(ctx, ocq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{oidcconnection.Label}
	default:
		return nil, &NotSingularError{oidcconnection.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (ocq *OIDCConnectionQuery) OnlyX(ctx context.Context) *OIDCConnection {
	node, err := ocq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only OIDCConnection ID in the query.
// Returns a *NotSingularError when more than one OIDCConnection ID is found.
// Returns a *NotFoundError when no entities are found.
func (ocq *OIDCConnectionQuery) OnlyID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = ocq.Limit(2).IDs(setContextOp(ctx, ocq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{oidcconnection.Label}
	default:
		err = &NotSingularError{oidcconnection.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (ocq *OIDCConnectionQuery) OnlyIDX(ctx context.Context) string {
	id, err := ocq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of OIDCConnections.
func (ocq *OIDCConnectionQuery) All(ctx context.Context) ([]*OIDCConnection, error) {
	ctx = setContextOp(ctx, ocq.ctx, "All")
	if err := ocq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*OIDCConnection, *OIDCConnectionQuery]()
	return withInterceptors[[]*OIDCConnection](ctx, ocq, qr, ocq.inters)
}

// AllX is like All, but panics if an error occurs.
func (ocq *OIDCConnectionQuery) AllX(ctx context.Context) []*OIDCConnection {
	nodes, err := ocq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of OIDCConnection IDs.
func (ocq *OIDCConnectionQuery) IDs(ctx context.Context) (ids []string, err error) {
	if ocq.ctx.Unique == nil && ocq.path != nil {
		ocq.Unique(true)
	}
	ctx = setContextOp(ctx, ocq.ctx, "IDs")
	if err = ocq.Select(oidcconnection.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (ocq *OIDCConnectionQuery) IDsX(ctx context.Context) []string {
	ids, err := ocq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (ocq *OIDCConnectionQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, ocq.ctx, "Count")
	if err := ocq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, ocq, querierCount[*OIDCConnectionQuery](), ocq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (ocq *OIDCConnectionQuery) CountX(ctx context.Context) int {
	count, err := ocq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (ocq *OIDCConnectionQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, ocq.ctx, "Exist")
	switch _, err := ocq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (ocq *OIDCConnectionQuery) ExistX(ctx context.Context) bool {
	exist, err := ocq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the OIDCConnectionQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (ocq *OIDCConnectionQuery) Clone() *OIDCConnectionQuery {
	if ocq == nil {
		return nil
	}
	return &OIDCConnectionQuery{
		config:               ocq.config,
		ctx:                  ocq.ctx.Clone(),
		order:                append([]oidcconnection.OrderOption{}, ocq.order...),
		inters:               append([]Interceptor{}, ocq.inters...),
		predicates:           append([]predicate.OIDCConnection{}, ocq.predicates...),
		withConnectionConfig: ocq.withConnectionConfig.Clone(),
		withUsers:            ocq.withUsers.Clone(),
		// clone intermediate query.
		sql:  ocq.sql.Clone(),
		path: ocq.path,
	}
}

// WithConnectionConfig tells the query-builder to eager-load the nodes that are connected to
// the "connection_config" edge. The optional arguments are used to configure the query builder of the edge.
func (ocq *OIDCConnectionQuery) WithConnectionConfig(opts ...func(*ConnectionConfigQuery)) *OIDCConnectionQuery {
	query := (&ConnectionConfigClient{config: ocq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	ocq.withConnectionConfig = query
	return ocq
}

// WithUsers tells the query-builder to eager-load the nodes that are connected to
// the "users" edge. The optional arguments are used to configure the query builder of the edge.
func (ocq *OIDCConnectionQuery) WithUsers(opts ...func(*UserQuery)) *OIDCConnectionQuery {
	query := (&UserClient{config: ocq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	ocq.withUsers = query
	return ocq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		Enabled bool `json:"enabled" hcl:"enabled"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.OIDCConnection.Query().
//		GroupBy(oidcconnection.FieldEnabled).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (ocq *OIDCConnectionQuery) GroupBy(field string, fields ...string) *OIDCConnectionGroupBy {
	ocq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &OIDCConnectionGroupBy{build: ocq}
	grbuild.flds = &ocq.ctx.Fields
	grbuild.label = oidcconnection.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		Enabled bool `json:"enabled" hcl:"enabled"`
//	}
//
//	client.OIDCConnection.Query().
//		Select(oidcconnection.FieldEnabled).
//		Scan(ctx, &v)
func (ocq *OIDCConnectionQuery) Select(fields ...string) *OIDCConnectionSelect {
	ocq.ctx.Fields = append(ocq.ctx.Fields, fields...)
	sbuild := &OIDCConnectionSelect{OIDCConnectionQuery: ocq}
	sbuild.label = oidcconnection.Label
	sbuild.flds, sbuild.scan = &ocq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a OIDCConnectionSelect configured with the given aggregations.
func (ocq *OIDCConnectionQuery) Aggregate(fns ...AggregateFunc) *OIDCConnectionSelect {
	return ocq.Select().Aggregate(fns...)
}

func (ocq *OIDCConnectionQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range ocq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, ocq); err != nil {
				return err
			}
		}
	}
	for _, f := range ocq.ctx.Fields {
		if !oidcconnection.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if ocq.path != nil {
		prev, err := ocq.path(ctx)
		if err != nil {
			return err
		}
		ocq.sql = prev
	}
	return nil
}

func (ocq *OIDCConnectionQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*OIDCConnection, error) {
	var (
		nodes       = []*OIDCConnection{}
		withFKs     = ocq.withFKs
		_spec       = ocq.querySpec()
		loadedTypes = [2]bool{
			ocq.withConnectionConfig != nil,
			ocq.withUsers != nil,
		}
	)
	if ocq.withConnectionConfig != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, oidcconnection.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*OIDCConnection).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &OIDCConnection{config: ocq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, ocq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := ocq.withConnectionConfig; query != nil {
		if err := ocq.loadConnectionConfig(ctx, query, nodes, nil,
			func(n *OIDCConnection, e *ConnectionConfig) { n.Edges.ConnectionConfig = e }); err != nil {
			return nil, err
		}
	}
	if query := ocq.withUsers; query != nil {
		if err := ocq.loadUsers(ctx, query, nodes, nil,
			func(n *OIDCConnection, e *User) { n.Edges.Users = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (ocq *OIDCConnectionQuery) loadConnectionConfig(ctx context.Context, query *ConnectionConfigQuery, nodes []*OIDCConnection, init func(*OIDCConnection), assign func(*OIDCConnection, *ConnectionConfig)) error {
	ids := make([]string, 0, len(nodes))
	nodeids := make(map[string][]*OIDCConnection)
	for i := range nodes {
		if nodes[i].connection_config_oidc_connections == nil {
			continue
		}
		fk := *nodes[i].connection_config_oidc_connections
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(connectionconfig.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "connection_config_oidc_connections" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (ocq *OIDCConnectionQuery) loadUsers(ctx context.Context, query *UserQuery, nodes []*OIDCConnection, init func(*OIDCConnection), assign func(*OIDCConnection, *User)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[string]*OIDCConnection)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
	}
	query.withFKs = true
	query.Where(predicate.User(func(s *sql.Selector) {
		s.Where(sql.InValues(s.C(oidcconnection.UsersColumn), fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.oidc_connection_users
		if fk == nil {
			return fmt.Errorf(`foreign-key "oidc_connection_users" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected referenced foreign-key "oidc_connection_users" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}

func (ocq *OIDCConnectionQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := ocq.querySpec()
	_spec.Node.Columns = ocq.ctx.Fields
	if len(ocq.ctx.Fields) > 0 {
		_spec.Unique = ocq.ctx.Unique != nil && *ocq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, ocq.driver, _spec)
}

func (ocq *OIDCConnectionQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(oidcconnection.Table, oidcconnection.Columns, sqlgraph.NewFieldSpec(oidcconnection.FieldID, field.TypeString))
	_spec.From = ocq.sql
	if unique := ocq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if ocq.path != nil {
		_spec.Unique = true
	}
	if fields := ocq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, oidcconnection.FieldID)
		for i := range fields {
			if fields[i] != oidcconnection.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := ocq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := ocq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := ocq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := ocq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (ocq *OIDCConnectionQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(ocq.driver.Dialect())
	t1 := builder.Table(oidcconnection.Table)
	columns := ocq.ctx.Fields
	if len(columns) == 0 {
		columns = oidcconnection.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if ocq.sql != nil {
		selector = ocq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if ocq.ctx.Unique != nil && *ocq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range ocq.predicates {
		p(selector)
	}
	for _, p := range ocq.order {
		p(selector)
	}
	if offset := ocq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := ocq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// OIDCConnectionGroupBy is the group-by builder for OIDCConnection entities.
type OIDCConnectionGroupBy struct {
	selector
	build *OIDCConnectionQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (ocgb *OIDCConnectionGroupBy) Aggregate(fns ...AggregateFunc) *OIDCConnectionGroupBy {
	ocgb.fns = append(ocgb.fns, fns...)
	return ocgb
}

// Scan applies the selector query and scans the result into the given value.
func (ocgb *OIDCConnectionGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, ocgb.build.ctx, "GroupBy")
	if err := ocgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*OIDCConnectionQuery, *OIDCConnectionGroupBy](ctx, ocgb.build, ocgb, ocgb.build.inters, v)
}

func (ocgb *OIDCConnectionGroupBy) sqlScan(ctx context.Context, root *OIDCConnectionQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(ocgb.fns))
	for _, fn := range ocgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*ocgb.flds)+len(ocgb.fns))
		for _, f := range *ocgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*ocgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := ocgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// OIDCConnectionSelect is the builder for selecting fields of OIDCConnection entities.
type OIDCConnectionSelect struct {
	*OIDCConnectionQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (ocs *OIDCConnectionSelect) Aggregate(fns ...AggregateFunc) *OIDCConnectionSelect {
	ocs.fns = append(ocs.fns, fns...)
	return ocs
}

// Scan applies the selector query and scans the result into the given value.
func (ocs *OIDCConnectionSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, ocs.ctx, "Select")
	if err := ocs.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*OIDCConnectionQuery, *OIDCConnectionSelect](ctx, ocs.OIDCConnectionQuery, ocs, ocs.inters, v)
}

func (ocs *OIDCConnectionSelect) sqlScan(ctx context.Context, root *OIDCConnectionQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(ocs.fns))
	for _, fn := range ocs.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*ocs.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := ocs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}