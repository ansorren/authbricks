// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"go.authbricks.com/bricks/ent/authorizationpayload"
	"go.authbricks.com/bricks/ent/predicate"
	"go.authbricks.com/bricks/ent/session"
)

// AuthorizationPayloadQuery is the builder for querying AuthorizationPayload entities.
type AuthorizationPayloadQuery struct {
	config
	ctx         *QueryContext
	order       []authorizationpayload.OrderOption
	inters      []Interceptor
	predicates  []predicate.AuthorizationPayload
	withSession *SessionQuery
	withFKs     bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the AuthorizationPayloadQuery builder.
func (apq *AuthorizationPayloadQuery) Where(ps ...predicate.AuthorizationPayload) *AuthorizationPayloadQuery {
	apq.predicates = append(apq.predicates, ps...)
	return apq
}

// Limit the number of records to be returned by this query.
func (apq *AuthorizationPayloadQuery) Limit(limit int) *AuthorizationPayloadQuery {
	apq.ctx.Limit = &limit
	return apq
}

// Offset to start from.
func (apq *AuthorizationPayloadQuery) Offset(offset int) *AuthorizationPayloadQuery {
	apq.ctx.Offset = &offset
	return apq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (apq *AuthorizationPayloadQuery) Unique(unique bool) *AuthorizationPayloadQuery {
	apq.ctx.Unique = &unique
	return apq
}

// Order specifies how the records should be ordered.
func (apq *AuthorizationPayloadQuery) Order(o ...authorizationpayload.OrderOption) *AuthorizationPayloadQuery {
	apq.order = append(apq.order, o...)
	return apq
}

// QuerySession chains the current query on the "session" edge.
func (apq *AuthorizationPayloadQuery) QuerySession() *SessionQuery {
	query := (&SessionClient{config: apq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := apq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := apq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(authorizationpayload.Table, authorizationpayload.FieldID, selector),
			sqlgraph.To(session.Table, session.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, authorizationpayload.SessionTable, authorizationpayload.SessionColumn),
		)
		fromU = sqlgraph.SetNeighbors(apq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first AuthorizationPayload entity from the query.
// Returns a *NotFoundError when no AuthorizationPayload was found.
func (apq *AuthorizationPayloadQuery) First(ctx context.Context) (*AuthorizationPayload, error) {
	nodes, err := apq.Limit(1).All(setContextOp(ctx, apq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{authorizationpayload.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (apq *AuthorizationPayloadQuery) FirstX(ctx context.Context) *AuthorizationPayload {
	node, err := apq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first AuthorizationPayload ID from the query.
// Returns a *NotFoundError when no AuthorizationPayload ID was found.
func (apq *AuthorizationPayloadQuery) FirstID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = apq.Limit(1).IDs(setContextOp(ctx, apq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{authorizationpayload.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (apq *AuthorizationPayloadQuery) FirstIDX(ctx context.Context) string {
	id, err := apq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single AuthorizationPayload entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one AuthorizationPayload entity is found.
// Returns a *NotFoundError when no AuthorizationPayload entities are found.
func (apq *AuthorizationPayloadQuery) Only(ctx context.Context) (*AuthorizationPayload, error) {
	nodes, err := apq.Limit(2).All(setContextOp(ctx, apq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{authorizationpayload.Label}
	default:
		return nil, &NotSingularError{authorizationpayload.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (apq *AuthorizationPayloadQuery) OnlyX(ctx context.Context) *AuthorizationPayload {
	node, err := apq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only AuthorizationPayload ID in the query.
// Returns a *NotSingularError when more than one AuthorizationPayload ID is found.
// Returns a *NotFoundError when no entities are found.
func (apq *AuthorizationPayloadQuery) OnlyID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = apq.Limit(2).IDs(setContextOp(ctx, apq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{authorizationpayload.Label}
	default:
		err = &NotSingularError{authorizationpayload.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (apq *AuthorizationPayloadQuery) OnlyIDX(ctx context.Context) string {
	id, err := apq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of AuthorizationPayloads.
func (apq *AuthorizationPayloadQuery) All(ctx context.Context) ([]*AuthorizationPayload, error) {
	ctx = setContextOp(ctx, apq.ctx, "All")
	if err := apq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*AuthorizationPayload, *AuthorizationPayloadQuery]()
	return withInterceptors[[]*AuthorizationPayload](ctx, apq, qr, apq.inters)
}

// AllX is like All, but panics if an error occurs.
func (apq *AuthorizationPayloadQuery) AllX(ctx context.Context) []*AuthorizationPayload {
	nodes, err := apq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of AuthorizationPayload IDs.
func (apq *AuthorizationPayloadQuery) IDs(ctx context.Context) (ids []string, err error) {
	if apq.ctx.Unique == nil && apq.path != nil {
		apq.Unique(true)
	}
	ctx = setContextOp(ctx, apq.ctx, "IDs")
	if err = apq.Select(authorizationpayload.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (apq *AuthorizationPayloadQuery) IDsX(ctx context.Context) []string {
	ids, err := apq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (apq *AuthorizationPayloadQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, apq.ctx, "Count")
	if err := apq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, apq, querierCount[*AuthorizationPayloadQuery](), apq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (apq *AuthorizationPayloadQuery) CountX(ctx context.Context) int {
	count, err := apq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (apq *AuthorizationPayloadQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, apq.ctx, "Exist")
	switch _, err := apq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (apq *AuthorizationPayloadQuery) ExistX(ctx context.Context) bool {
	exist, err := apq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the AuthorizationPayloadQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (apq *AuthorizationPayloadQuery) Clone() *AuthorizationPayloadQuery {
	if apq == nil {
		return nil
	}
	return &AuthorizationPayloadQuery{
		config:      apq.config,
		ctx:         apq.ctx.Clone(),
		order:       append([]authorizationpayload.OrderOption{}, apq.order...),
		inters:      append([]Interceptor{}, apq.inters...),
		predicates:  append([]predicate.AuthorizationPayload{}, apq.predicates...),
		withSession: apq.withSession.Clone(),
		// clone intermediate query.
		sql:  apq.sql.Clone(),
		path: apq.path,
	}
}

// WithSession tells the query-builder to eager-load the nodes that are connected to
// the "session" edge. The optional arguments are used to configure the query builder of the edge.
func (apq *AuthorizationPayloadQuery) WithSession(opts ...func(*SessionQuery)) *AuthorizationPayloadQuery {
	query := (&SessionClient{config: apq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	apq.withSession = query
	return apq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		CodeChallenge string `json:"code_challenge"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.AuthorizationPayload.Query().
//		GroupBy(authorizationpayload.FieldCodeChallenge).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (apq *AuthorizationPayloadQuery) GroupBy(field string, fields ...string) *AuthorizationPayloadGroupBy {
	apq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &AuthorizationPayloadGroupBy{build: apq}
	grbuild.flds = &apq.ctx.Fields
	grbuild.label = authorizationpayload.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		CodeChallenge string `json:"code_challenge"`
//	}
//
//	client.AuthorizationPayload.Query().
//		Select(authorizationpayload.FieldCodeChallenge).
//		Scan(ctx, &v)
func (apq *AuthorizationPayloadQuery) Select(fields ...string) *AuthorizationPayloadSelect {
	apq.ctx.Fields = append(apq.ctx.Fields, fields...)
	sbuild := &AuthorizationPayloadSelect{AuthorizationPayloadQuery: apq}
	sbuild.label = authorizationpayload.Label
	sbuild.flds, sbuild.scan = &apq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a AuthorizationPayloadSelect configured with the given aggregations.
func (apq *AuthorizationPayloadQuery) Aggregate(fns ...AggregateFunc) *AuthorizationPayloadSelect {
	return apq.Select().Aggregate(fns...)
}

func (apq *AuthorizationPayloadQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range apq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, apq); err != nil {
				return err
			}
		}
	}
	for _, f := range apq.ctx.Fields {
		if !authorizationpayload.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if apq.path != nil {
		prev, err := apq.path(ctx)
		if err != nil {
			return err
		}
		apq.sql = prev
	}
	return nil
}

func (apq *AuthorizationPayloadQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*AuthorizationPayload, error) {
	var (
		nodes       = []*AuthorizationPayload{}
		withFKs     = apq.withFKs
		_spec       = apq.querySpec()
		loadedTypes = [1]bool{
			apq.withSession != nil,
		}
	)
	if apq.withSession != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, authorizationpayload.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*AuthorizationPayload).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &AuthorizationPayload{config: apq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, apq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := apq.withSession; query != nil {
		if err := apq.loadSession(ctx, query, nodes, nil,
			func(n *AuthorizationPayload, e *Session) { n.Edges.Session = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (apq *AuthorizationPayloadQuery) loadSession(ctx context.Context, query *SessionQuery, nodes []*AuthorizationPayload, init func(*AuthorizationPayload), assign func(*AuthorizationPayload, *Session)) error {
	ids := make([]string, 0, len(nodes))
	nodeids := make(map[string][]*AuthorizationPayload)
	for i := range nodes {
		if nodes[i].session_authorization_payload == nil {
			continue
		}
		fk := *nodes[i].session_authorization_payload
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(session.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "session_authorization_payload" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (apq *AuthorizationPayloadQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := apq.querySpec()
	_spec.Node.Columns = apq.ctx.Fields
	if len(apq.ctx.Fields) > 0 {
		_spec.Unique = apq.ctx.Unique != nil && *apq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, apq.driver, _spec)
}

func (apq *AuthorizationPayloadQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(authorizationpayload.Table, authorizationpayload.Columns, sqlgraph.NewFieldSpec(authorizationpayload.FieldID, field.TypeString))
	_spec.From = apq.sql
	if unique := apq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if apq.path != nil {
		_spec.Unique = true
	}
	if fields := apq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, authorizationpayload.FieldID)
		for i := range fields {
			if fields[i] != authorizationpayload.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := apq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := apq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := apq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := apq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (apq *AuthorizationPayloadQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(apq.driver.Dialect())
	t1 := builder.Table(authorizationpayload.Table)
	columns := apq.ctx.Fields
	if len(columns) == 0 {
		columns = authorizationpayload.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if apq.sql != nil {
		selector = apq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if apq.ctx.Unique != nil && *apq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range apq.predicates {
		p(selector)
	}
	for _, p := range apq.order {
		p(selector)
	}
	if offset := apq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := apq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// AuthorizationPayloadGroupBy is the group-by builder for AuthorizationPayload entities.
type AuthorizationPayloadGroupBy struct {
	selector
	build *AuthorizationPayloadQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (apgb *AuthorizationPayloadGroupBy) Aggregate(fns ...AggregateFunc) *AuthorizationPayloadGroupBy {
	apgb.fns = append(apgb.fns, fns...)
	return apgb
}

// Scan applies the selector query and scans the result into the given value.
func (apgb *AuthorizationPayloadGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, apgb.build.ctx, "GroupBy")
	if err := apgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*AuthorizationPayloadQuery, *AuthorizationPayloadGroupBy](ctx, apgb.build, apgb, apgb.build.inters, v)
}

func (apgb *AuthorizationPayloadGroupBy) sqlScan(ctx context.Context, root *AuthorizationPayloadQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(apgb.fns))
	for _, fn := range apgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*apgb.flds)+len(apgb.fns))
		for _, f := range *apgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*apgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := apgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// AuthorizationPayloadSelect is the builder for selecting fields of AuthorizationPayload entities.
type AuthorizationPayloadSelect struct {
	*AuthorizationPayloadQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (aps *AuthorizationPayloadSelect) Aggregate(fns ...AggregateFunc) *AuthorizationPayloadSelect {
	aps.fns = append(aps.fns, fns...)
	return aps
}

// Scan applies the selector query and scans the result into the given value.
func (aps *AuthorizationPayloadSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, aps.ctx, "Select")
	if err := aps.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*AuthorizationPayloadQuery, *AuthorizationPayloadSelect](ctx, aps.AuthorizationPayloadQuery, aps, aps.inters, v)
}

func (aps *AuthorizationPayloadSelect) sqlScan(ctx context.Context, root *AuthorizationPayloadQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(aps.fns))
	for _, fn := range aps.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*aps.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := aps.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
