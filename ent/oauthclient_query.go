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
	"go.authbricks.com/bricks/ent/codegrant"
	"go.authbricks.com/bricks/ent/credentials"
	"go.authbricks.com/bricks/ent/m2mgrant"
	"go.authbricks.com/bricks/ent/oauthclient"
	"go.authbricks.com/bricks/ent/oauthserver"
	"go.authbricks.com/bricks/ent/predicate"
)

// OAuthClientQuery is the builder for querying OAuthClient entities.
type OAuthClientQuery struct {
	config
	ctx             *QueryContext
	order           []oauthclient.OrderOption
	inters          []Interceptor
	predicates      []predicate.OAuthClient
	withM2mGrants   *M2MGrantQuery
	withCodeGrants  *CodeGrantQuery
	withCredentials *CredentialsQuery
	withServer      *OAuthServerQuery
	withFKs         bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the OAuthClientQuery builder.
func (ocq *OAuthClientQuery) Where(ps ...predicate.OAuthClient) *OAuthClientQuery {
	ocq.predicates = append(ocq.predicates, ps...)
	return ocq
}

// Limit the number of records to be returned by this query.
func (ocq *OAuthClientQuery) Limit(limit int) *OAuthClientQuery {
	ocq.ctx.Limit = &limit
	return ocq
}

// Offset to start from.
func (ocq *OAuthClientQuery) Offset(offset int) *OAuthClientQuery {
	ocq.ctx.Offset = &offset
	return ocq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (ocq *OAuthClientQuery) Unique(unique bool) *OAuthClientQuery {
	ocq.ctx.Unique = &unique
	return ocq
}

// Order specifies how the records should be ordered.
func (ocq *OAuthClientQuery) Order(o ...oauthclient.OrderOption) *OAuthClientQuery {
	ocq.order = append(ocq.order, o...)
	return ocq
}

// QueryM2mGrants chains the current query on the "m2m_grants" edge.
func (ocq *OAuthClientQuery) QueryM2mGrants() *M2MGrantQuery {
	query := (&M2MGrantClient{config: ocq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := ocq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := ocq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(oauthclient.Table, oauthclient.FieldID, selector),
			sqlgraph.To(m2mgrant.Table, m2mgrant.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, false, oauthclient.M2mGrantsTable, oauthclient.M2mGrantsColumn),
		)
		fromU = sqlgraph.SetNeighbors(ocq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryCodeGrants chains the current query on the "code_grants" edge.
func (ocq *OAuthClientQuery) QueryCodeGrants() *CodeGrantQuery {
	query := (&CodeGrantClient{config: ocq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := ocq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := ocq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(oauthclient.Table, oauthclient.FieldID, selector),
			sqlgraph.To(codegrant.Table, codegrant.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, false, oauthclient.CodeGrantsTable, oauthclient.CodeGrantsColumn),
		)
		fromU = sqlgraph.SetNeighbors(ocq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryCredentials chains the current query on the "credentials" edge.
func (ocq *OAuthClientQuery) QueryCredentials() *CredentialsQuery {
	query := (&CredentialsClient{config: ocq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := ocq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := ocq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(oauthclient.Table, oauthclient.FieldID, selector),
			sqlgraph.To(credentials.Table, credentials.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, oauthclient.CredentialsTable, oauthclient.CredentialsColumn),
		)
		fromU = sqlgraph.SetNeighbors(ocq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryServer chains the current query on the "server" edge.
func (ocq *OAuthClientQuery) QueryServer() *OAuthServerQuery {
	query := (&OAuthServerClient{config: ocq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := ocq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := ocq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(oauthclient.Table, oauthclient.FieldID, selector),
			sqlgraph.To(oauthserver.Table, oauthserver.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, oauthclient.ServerTable, oauthclient.ServerColumn),
		)
		fromU = sqlgraph.SetNeighbors(ocq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first OAuthClient entity from the query.
// Returns a *NotFoundError when no OAuthClient was found.
func (ocq *OAuthClientQuery) First(ctx context.Context) (*OAuthClient, error) {
	nodes, err := ocq.Limit(1).All(setContextOp(ctx, ocq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{oauthclient.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (ocq *OAuthClientQuery) FirstX(ctx context.Context) *OAuthClient {
	node, err := ocq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first OAuthClient ID from the query.
// Returns a *NotFoundError when no OAuthClient ID was found.
func (ocq *OAuthClientQuery) FirstID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = ocq.Limit(1).IDs(setContextOp(ctx, ocq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{oauthclient.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (ocq *OAuthClientQuery) FirstIDX(ctx context.Context) string {
	id, err := ocq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single OAuthClient entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one OAuthClient entity is found.
// Returns a *NotFoundError when no OAuthClient entities are found.
func (ocq *OAuthClientQuery) Only(ctx context.Context) (*OAuthClient, error) {
	nodes, err := ocq.Limit(2).All(setContextOp(ctx, ocq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{oauthclient.Label}
	default:
		return nil, &NotSingularError{oauthclient.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (ocq *OAuthClientQuery) OnlyX(ctx context.Context) *OAuthClient {
	node, err := ocq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only OAuthClient ID in the query.
// Returns a *NotSingularError when more than one OAuthClient ID is found.
// Returns a *NotFoundError when no entities are found.
func (ocq *OAuthClientQuery) OnlyID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = ocq.Limit(2).IDs(setContextOp(ctx, ocq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{oauthclient.Label}
	default:
		err = &NotSingularError{oauthclient.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (ocq *OAuthClientQuery) OnlyIDX(ctx context.Context) string {
	id, err := ocq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of OAuthClients.
func (ocq *OAuthClientQuery) All(ctx context.Context) ([]*OAuthClient, error) {
	ctx = setContextOp(ctx, ocq.ctx, "All")
	if err := ocq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*OAuthClient, *OAuthClientQuery]()
	return withInterceptors[[]*OAuthClient](ctx, ocq, qr, ocq.inters)
}

// AllX is like All, but panics if an error occurs.
func (ocq *OAuthClientQuery) AllX(ctx context.Context) []*OAuthClient {
	nodes, err := ocq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of OAuthClient IDs.
func (ocq *OAuthClientQuery) IDs(ctx context.Context) (ids []string, err error) {
	if ocq.ctx.Unique == nil && ocq.path != nil {
		ocq.Unique(true)
	}
	ctx = setContextOp(ctx, ocq.ctx, "IDs")
	if err = ocq.Select(oauthclient.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (ocq *OAuthClientQuery) IDsX(ctx context.Context) []string {
	ids, err := ocq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (ocq *OAuthClientQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, ocq.ctx, "Count")
	if err := ocq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, ocq, querierCount[*OAuthClientQuery](), ocq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (ocq *OAuthClientQuery) CountX(ctx context.Context) int {
	count, err := ocq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (ocq *OAuthClientQuery) Exist(ctx context.Context) (bool, error) {
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
func (ocq *OAuthClientQuery) ExistX(ctx context.Context) bool {
	exist, err := ocq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the OAuthClientQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (ocq *OAuthClientQuery) Clone() *OAuthClientQuery {
	if ocq == nil {
		return nil
	}
	return &OAuthClientQuery{
		config:          ocq.config,
		ctx:             ocq.ctx.Clone(),
		order:           append([]oauthclient.OrderOption{}, ocq.order...),
		inters:          append([]Interceptor{}, ocq.inters...),
		predicates:      append([]predicate.OAuthClient{}, ocq.predicates...),
		withM2mGrants:   ocq.withM2mGrants.Clone(),
		withCodeGrants:  ocq.withCodeGrants.Clone(),
		withCredentials: ocq.withCredentials.Clone(),
		withServer:      ocq.withServer.Clone(),
		// clone intermediate query.
		sql:  ocq.sql.Clone(),
		path: ocq.path,
	}
}

// WithM2mGrants tells the query-builder to eager-load the nodes that are connected to
// the "m2m_grants" edge. The optional arguments are used to configure the query builder of the edge.
func (ocq *OAuthClientQuery) WithM2mGrants(opts ...func(*M2MGrantQuery)) *OAuthClientQuery {
	query := (&M2MGrantClient{config: ocq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	ocq.withM2mGrants = query
	return ocq
}

// WithCodeGrants tells the query-builder to eager-load the nodes that are connected to
// the "code_grants" edge. The optional arguments are used to configure the query builder of the edge.
func (ocq *OAuthClientQuery) WithCodeGrants(opts ...func(*CodeGrantQuery)) *OAuthClientQuery {
	query := (&CodeGrantClient{config: ocq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	ocq.withCodeGrants = query
	return ocq
}

// WithCredentials tells the query-builder to eager-load the nodes that are connected to
// the "credentials" edge. The optional arguments are used to configure the query builder of the edge.
func (ocq *OAuthClientQuery) WithCredentials(opts ...func(*CredentialsQuery)) *OAuthClientQuery {
	query := (&CredentialsClient{config: ocq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	ocq.withCredentials = query
	return ocq
}

// WithServer tells the query-builder to eager-load the nodes that are connected to
// the "server" edge. The optional arguments are used to configure the query builder of the edge.
func (ocq *OAuthClientQuery) WithServer(opts ...func(*OAuthServerQuery)) *OAuthClientQuery {
	query := (&OAuthServerClient{config: ocq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	ocq.withServer = query
	return ocq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		Name string `json:"name"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.OAuthClient.Query().
//		GroupBy(oauthclient.FieldName).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (ocq *OAuthClientQuery) GroupBy(field string, fields ...string) *OAuthClientGroupBy {
	ocq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &OAuthClientGroupBy{build: ocq}
	grbuild.flds = &ocq.ctx.Fields
	grbuild.label = oauthclient.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		Name string `json:"name"`
//	}
//
//	client.OAuthClient.Query().
//		Select(oauthclient.FieldName).
//		Scan(ctx, &v)
func (ocq *OAuthClientQuery) Select(fields ...string) *OAuthClientSelect {
	ocq.ctx.Fields = append(ocq.ctx.Fields, fields...)
	sbuild := &OAuthClientSelect{OAuthClientQuery: ocq}
	sbuild.label = oauthclient.Label
	sbuild.flds, sbuild.scan = &ocq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a OAuthClientSelect configured with the given aggregations.
func (ocq *OAuthClientQuery) Aggregate(fns ...AggregateFunc) *OAuthClientSelect {
	return ocq.Select().Aggregate(fns...)
}

func (ocq *OAuthClientQuery) prepareQuery(ctx context.Context) error {
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
		if !oauthclient.ValidColumn(f) {
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

func (ocq *OAuthClientQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*OAuthClient, error) {
	var (
		nodes       = []*OAuthClient{}
		withFKs     = ocq.withFKs
		_spec       = ocq.querySpec()
		loadedTypes = [4]bool{
			ocq.withM2mGrants != nil,
			ocq.withCodeGrants != nil,
			ocq.withCredentials != nil,
			ocq.withServer != nil,
		}
	)
	if ocq.withServer != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, oauthclient.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*OAuthClient).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &OAuthClient{config: ocq.config}
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
	if query := ocq.withM2mGrants; query != nil {
		if err := ocq.loadM2mGrants(ctx, query, nodes, nil,
			func(n *OAuthClient, e *M2MGrant) { n.Edges.M2mGrants = e }); err != nil {
			return nil, err
		}
	}
	if query := ocq.withCodeGrants; query != nil {
		if err := ocq.loadCodeGrants(ctx, query, nodes, nil,
			func(n *OAuthClient, e *CodeGrant) { n.Edges.CodeGrants = e }); err != nil {
			return nil, err
		}
	}
	if query := ocq.withCredentials; query != nil {
		if err := ocq.loadCredentials(ctx, query, nodes,
			func(n *OAuthClient) { n.Edges.Credentials = []*Credentials{} },
			func(n *OAuthClient, e *Credentials) { n.Edges.Credentials = append(n.Edges.Credentials, e) }); err != nil {
			return nil, err
		}
	}
	if query := ocq.withServer; query != nil {
		if err := ocq.loadServer(ctx, query, nodes, nil,
			func(n *OAuthClient, e *OAuthServer) { n.Edges.Server = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (ocq *OAuthClientQuery) loadM2mGrants(ctx context.Context, query *M2MGrantQuery, nodes []*OAuthClient, init func(*OAuthClient), assign func(*OAuthClient, *M2MGrant)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[string]*OAuthClient)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
	}
	query.withFKs = true
	query.Where(predicate.M2MGrant(func(s *sql.Selector) {
		s.Where(sql.InValues(s.C(oauthclient.M2mGrantsColumn), fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.oauth_client_m2m_grants
		if fk == nil {
			return fmt.Errorf(`foreign-key "oauth_client_m2m_grants" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected referenced foreign-key "oauth_client_m2m_grants" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}
func (ocq *OAuthClientQuery) loadCodeGrants(ctx context.Context, query *CodeGrantQuery, nodes []*OAuthClient, init func(*OAuthClient), assign func(*OAuthClient, *CodeGrant)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[string]*OAuthClient)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
	}
	query.withFKs = true
	query.Where(predicate.CodeGrant(func(s *sql.Selector) {
		s.Where(sql.InValues(s.C(oauthclient.CodeGrantsColumn), fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.oauth_client_code_grants
		if fk == nil {
			return fmt.Errorf(`foreign-key "oauth_client_code_grants" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected referenced foreign-key "oauth_client_code_grants" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}
func (ocq *OAuthClientQuery) loadCredentials(ctx context.Context, query *CredentialsQuery, nodes []*OAuthClient, init func(*OAuthClient), assign func(*OAuthClient, *Credentials)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[string]*OAuthClient)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
		if init != nil {
			init(nodes[i])
		}
	}
	query.withFKs = true
	query.Where(predicate.Credentials(func(s *sql.Selector) {
		s.Where(sql.InValues(s.C(oauthclient.CredentialsColumn), fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.oauth_client_credentials
		if fk == nil {
			return fmt.Errorf(`foreign-key "oauth_client_credentials" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected referenced foreign-key "oauth_client_credentials" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}
func (ocq *OAuthClientQuery) loadServer(ctx context.Context, query *OAuthServerQuery, nodes []*OAuthClient, init func(*OAuthClient), assign func(*OAuthClient, *OAuthServer)) error {
	ids := make([]int, 0, len(nodes))
	nodeids := make(map[int][]*OAuthClient)
	for i := range nodes {
		if nodes[i].oauth_server_clients == nil {
			continue
		}
		fk := *nodes[i].oauth_server_clients
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(oauthserver.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "oauth_server_clients" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (ocq *OAuthClientQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := ocq.querySpec()
	_spec.Node.Columns = ocq.ctx.Fields
	if len(ocq.ctx.Fields) > 0 {
		_spec.Unique = ocq.ctx.Unique != nil && *ocq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, ocq.driver, _spec)
}

func (ocq *OAuthClientQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(oauthclient.Table, oauthclient.Columns, sqlgraph.NewFieldSpec(oauthclient.FieldID, field.TypeString))
	_spec.From = ocq.sql
	if unique := ocq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if ocq.path != nil {
		_spec.Unique = true
	}
	if fields := ocq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, oauthclient.FieldID)
		for i := range fields {
			if fields[i] != oauthclient.FieldID {
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

func (ocq *OAuthClientQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(ocq.driver.Dialect())
	t1 := builder.Table(oauthclient.Table)
	columns := ocq.ctx.Fields
	if len(columns) == 0 {
		columns = oauthclient.Columns
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

// OAuthClientGroupBy is the group-by builder for OAuthClient entities.
type OAuthClientGroupBy struct {
	selector
	build *OAuthClientQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (ocgb *OAuthClientGroupBy) Aggregate(fns ...AggregateFunc) *OAuthClientGroupBy {
	ocgb.fns = append(ocgb.fns, fns...)
	return ocgb
}

// Scan applies the selector query and scans the result into the given value.
func (ocgb *OAuthClientGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, ocgb.build.ctx, "GroupBy")
	if err := ocgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*OAuthClientQuery, *OAuthClientGroupBy](ctx, ocgb.build, ocgb, ocgb.build.inters, v)
}

func (ocgb *OAuthClientGroupBy) sqlScan(ctx context.Context, root *OAuthClientQuery, v any) error {
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

// OAuthClientSelect is the builder for selecting fields of OAuthClient entities.
type OAuthClientSelect struct {
	*OAuthClientQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (ocs *OAuthClientSelect) Aggregate(fns ...AggregateFunc) *OAuthClientSelect {
	ocs.fns = append(ocs.fns, fns...)
	return ocs
}

// Scan applies the selector query and scans the result into the given value.
func (ocs *OAuthClientSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, ocs.ctx, "Select")
	if err := ocs.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*OAuthClientQuery, *OAuthClientSelect](ctx, ocs.OAuthClientQuery, ocs, ocs.inters, v)
}

func (ocs *OAuthClientSelect) sqlScan(ctx context.Context, root *OAuthClientQuery, v any) error {
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