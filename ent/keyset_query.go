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
	"go.authbricks.com/bricks/ent/predicate"
	"go.authbricks.com/bricks/ent/service"
	"go.authbricks.com/bricks/ent/signingkey"
)

// KeySetQuery is the builder for querying KeySet entities.
type KeySetQuery struct {
	config
	ctx             *QueryContext
	order           []keyset.OrderOption
	inters          []Interceptor
	predicates      []predicate.KeySet
	withService     *ServiceQuery
	withSigningKeys *SigningKeyQuery
	withFKs         bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the KeySetQuery builder.
func (ksq *KeySetQuery) Where(ps ...predicate.KeySet) *KeySetQuery {
	ksq.predicates = append(ksq.predicates, ps...)
	return ksq
}

// Limit the number of records to be returned by this query.
func (ksq *KeySetQuery) Limit(limit int) *KeySetQuery {
	ksq.ctx.Limit = &limit
	return ksq
}

// Offset to start from.
func (ksq *KeySetQuery) Offset(offset int) *KeySetQuery {
	ksq.ctx.Offset = &offset
	return ksq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (ksq *KeySetQuery) Unique(unique bool) *KeySetQuery {
	ksq.ctx.Unique = &unique
	return ksq
}

// Order specifies how the records should be ordered.
func (ksq *KeySetQuery) Order(o ...keyset.OrderOption) *KeySetQuery {
	ksq.order = append(ksq.order, o...)
	return ksq
}

// QueryService chains the current query on the "service" edge.
func (ksq *KeySetQuery) QueryService() *ServiceQuery {
	query := (&ServiceClient{config: ksq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := ksq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := ksq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(keyset.Table, keyset.FieldID, selector),
			sqlgraph.To(service.Table, service.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, keyset.ServiceTable, keyset.ServiceColumn),
		)
		fromU = sqlgraph.SetNeighbors(ksq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QuerySigningKeys chains the current query on the "signing_keys" edge.
func (ksq *KeySetQuery) QuerySigningKeys() *SigningKeyQuery {
	query := (&SigningKeyClient{config: ksq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := ksq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := ksq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(keyset.Table, keyset.FieldID, selector),
			sqlgraph.To(signingkey.Table, signingkey.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, keyset.SigningKeysTable, keyset.SigningKeysColumn),
		)
		fromU = sqlgraph.SetNeighbors(ksq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first KeySet entity from the query.
// Returns a *NotFoundError when no KeySet was found.
func (ksq *KeySetQuery) First(ctx context.Context) (*KeySet, error) {
	nodes, err := ksq.Limit(1).All(setContextOp(ctx, ksq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{keyset.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (ksq *KeySetQuery) FirstX(ctx context.Context) *KeySet {
	node, err := ksq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first KeySet ID from the query.
// Returns a *NotFoundError when no KeySet ID was found.
func (ksq *KeySetQuery) FirstID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = ksq.Limit(1).IDs(setContextOp(ctx, ksq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{keyset.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (ksq *KeySetQuery) FirstIDX(ctx context.Context) string {
	id, err := ksq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single KeySet entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one KeySet entity is found.
// Returns a *NotFoundError when no KeySet entities are found.
func (ksq *KeySetQuery) Only(ctx context.Context) (*KeySet, error) {
	nodes, err := ksq.Limit(2).All(setContextOp(ctx, ksq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{keyset.Label}
	default:
		return nil, &NotSingularError{keyset.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (ksq *KeySetQuery) OnlyX(ctx context.Context) *KeySet {
	node, err := ksq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only KeySet ID in the query.
// Returns a *NotSingularError when more than one KeySet ID is found.
// Returns a *NotFoundError when no entities are found.
func (ksq *KeySetQuery) OnlyID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = ksq.Limit(2).IDs(setContextOp(ctx, ksq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{keyset.Label}
	default:
		err = &NotSingularError{keyset.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (ksq *KeySetQuery) OnlyIDX(ctx context.Context) string {
	id, err := ksq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of KeySets.
func (ksq *KeySetQuery) All(ctx context.Context) ([]*KeySet, error) {
	ctx = setContextOp(ctx, ksq.ctx, "All")
	if err := ksq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*KeySet, *KeySetQuery]()
	return withInterceptors[[]*KeySet](ctx, ksq, qr, ksq.inters)
}

// AllX is like All, but panics if an error occurs.
func (ksq *KeySetQuery) AllX(ctx context.Context) []*KeySet {
	nodes, err := ksq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of KeySet IDs.
func (ksq *KeySetQuery) IDs(ctx context.Context) (ids []string, err error) {
	if ksq.ctx.Unique == nil && ksq.path != nil {
		ksq.Unique(true)
	}
	ctx = setContextOp(ctx, ksq.ctx, "IDs")
	if err = ksq.Select(keyset.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (ksq *KeySetQuery) IDsX(ctx context.Context) []string {
	ids, err := ksq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (ksq *KeySetQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, ksq.ctx, "Count")
	if err := ksq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, ksq, querierCount[*KeySetQuery](), ksq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (ksq *KeySetQuery) CountX(ctx context.Context) int {
	count, err := ksq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (ksq *KeySetQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, ksq.ctx, "Exist")
	switch _, err := ksq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (ksq *KeySetQuery) ExistX(ctx context.Context) bool {
	exist, err := ksq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the KeySetQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (ksq *KeySetQuery) Clone() *KeySetQuery {
	if ksq == nil {
		return nil
	}
	return &KeySetQuery{
		config:          ksq.config,
		ctx:             ksq.ctx.Clone(),
		order:           append([]keyset.OrderOption{}, ksq.order...),
		inters:          append([]Interceptor{}, ksq.inters...),
		predicates:      append([]predicate.KeySet{}, ksq.predicates...),
		withService:     ksq.withService.Clone(),
		withSigningKeys: ksq.withSigningKeys.Clone(),
		// clone intermediate query.
		sql:  ksq.sql.Clone(),
		path: ksq.path,
	}
}

// WithService tells the query-builder to eager-load the nodes that are connected to
// the "service" edge. The optional arguments are used to configure the query builder of the edge.
func (ksq *KeySetQuery) WithService(opts ...func(*ServiceQuery)) *KeySetQuery {
	query := (&ServiceClient{config: ksq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	ksq.withService = query
	return ksq
}

// WithSigningKeys tells the query-builder to eager-load the nodes that are connected to
// the "signing_keys" edge. The optional arguments are used to configure the query builder of the edge.
func (ksq *KeySetQuery) WithSigningKeys(opts ...func(*SigningKeyQuery)) *KeySetQuery {
	query := (&SigningKeyClient{config: ksq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	ksq.withSigningKeys = query
	return ksq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
func (ksq *KeySetQuery) GroupBy(field string, fields ...string) *KeySetGroupBy {
	ksq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &KeySetGroupBy{build: ksq}
	grbuild.flds = &ksq.ctx.Fields
	grbuild.label = keyset.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
func (ksq *KeySetQuery) Select(fields ...string) *KeySetSelect {
	ksq.ctx.Fields = append(ksq.ctx.Fields, fields...)
	sbuild := &KeySetSelect{KeySetQuery: ksq}
	sbuild.label = keyset.Label
	sbuild.flds, sbuild.scan = &ksq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a KeySetSelect configured with the given aggregations.
func (ksq *KeySetQuery) Aggregate(fns ...AggregateFunc) *KeySetSelect {
	return ksq.Select().Aggregate(fns...)
}

func (ksq *KeySetQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range ksq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, ksq); err != nil {
				return err
			}
		}
	}
	for _, f := range ksq.ctx.Fields {
		if !keyset.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if ksq.path != nil {
		prev, err := ksq.path(ctx)
		if err != nil {
			return err
		}
		ksq.sql = prev
	}
	return nil
}

func (ksq *KeySetQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*KeySet, error) {
	var (
		nodes       = []*KeySet{}
		withFKs     = ksq.withFKs
		_spec       = ksq.querySpec()
		loadedTypes = [2]bool{
			ksq.withService != nil,
			ksq.withSigningKeys != nil,
		}
	)
	if ksq.withService != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, keyset.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*KeySet).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &KeySet{config: ksq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, ksq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := ksq.withService; query != nil {
		if err := ksq.loadService(ctx, query, nodes, nil,
			func(n *KeySet, e *Service) { n.Edges.Service = e }); err != nil {
			return nil, err
		}
	}
	if query := ksq.withSigningKeys; query != nil {
		if err := ksq.loadSigningKeys(ctx, query, nodes,
			func(n *KeySet) { n.Edges.SigningKeys = []*SigningKey{} },
			func(n *KeySet, e *SigningKey) { n.Edges.SigningKeys = append(n.Edges.SigningKeys, e) }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (ksq *KeySetQuery) loadService(ctx context.Context, query *ServiceQuery, nodes []*KeySet, init func(*KeySet), assign func(*KeySet, *Service)) error {
	ids := make([]string, 0, len(nodes))
	nodeids := make(map[string][]*KeySet)
	for i := range nodes {
		if nodes[i].service_key_set == nil {
			continue
		}
		fk := *nodes[i].service_key_set
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
			return fmt.Errorf(`unexpected foreign-key "service_key_set" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (ksq *KeySetQuery) loadSigningKeys(ctx context.Context, query *SigningKeyQuery, nodes []*KeySet, init func(*KeySet), assign func(*KeySet, *SigningKey)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[string]*KeySet)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
		if init != nil {
			init(nodes[i])
		}
	}
	query.withFKs = true
	query.Where(predicate.SigningKey(func(s *sql.Selector) {
		s.Where(sql.InValues(s.C(keyset.SigningKeysColumn), fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.key_set_signing_keys
		if fk == nil {
			return fmt.Errorf(`foreign-key "key_set_signing_keys" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected referenced foreign-key "key_set_signing_keys" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}

func (ksq *KeySetQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := ksq.querySpec()
	_spec.Node.Columns = ksq.ctx.Fields
	if len(ksq.ctx.Fields) > 0 {
		_spec.Unique = ksq.ctx.Unique != nil && *ksq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, ksq.driver, _spec)
}

func (ksq *KeySetQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(keyset.Table, keyset.Columns, sqlgraph.NewFieldSpec(keyset.FieldID, field.TypeString))
	_spec.From = ksq.sql
	if unique := ksq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if ksq.path != nil {
		_spec.Unique = true
	}
	if fields := ksq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, keyset.FieldID)
		for i := range fields {
			if fields[i] != keyset.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := ksq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := ksq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := ksq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := ksq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (ksq *KeySetQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(ksq.driver.Dialect())
	t1 := builder.Table(keyset.Table)
	columns := ksq.ctx.Fields
	if len(columns) == 0 {
		columns = keyset.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if ksq.sql != nil {
		selector = ksq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if ksq.ctx.Unique != nil && *ksq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range ksq.predicates {
		p(selector)
	}
	for _, p := range ksq.order {
		p(selector)
	}
	if offset := ksq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := ksq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// KeySetGroupBy is the group-by builder for KeySet entities.
type KeySetGroupBy struct {
	selector
	build *KeySetQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (ksgb *KeySetGroupBy) Aggregate(fns ...AggregateFunc) *KeySetGroupBy {
	ksgb.fns = append(ksgb.fns, fns...)
	return ksgb
}

// Scan applies the selector query and scans the result into the given value.
func (ksgb *KeySetGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, ksgb.build.ctx, "GroupBy")
	if err := ksgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*KeySetQuery, *KeySetGroupBy](ctx, ksgb.build, ksgb, ksgb.build.inters, v)
}

func (ksgb *KeySetGroupBy) sqlScan(ctx context.Context, root *KeySetQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(ksgb.fns))
	for _, fn := range ksgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*ksgb.flds)+len(ksgb.fns))
		for _, f := range *ksgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*ksgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := ksgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// KeySetSelect is the builder for selecting fields of KeySet entities.
type KeySetSelect struct {
	*KeySetQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (kss *KeySetSelect) Aggregate(fns ...AggregateFunc) *KeySetSelect {
	kss.fns = append(kss.fns, fns...)
	return kss
}

// Scan applies the selector query and scans the result into the given value.
func (kss *KeySetSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, kss.ctx, "Select")
	if err := kss.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*KeySetQuery, *KeySetSelect](ctx, kss.KeySetQuery, kss, kss.inters, v)
}

func (kss *KeySetSelect) sqlScan(ctx context.Context, root *KeySetQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(kss.fns))
	for _, fn := range kss.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*kss.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := kss.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
