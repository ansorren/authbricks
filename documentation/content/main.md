---
weight: 10
title: AuthBricks
---

# AuthBricks

AuthBricks is a Go library for building Identity and Access Management solutions.
It aims to provide simple primitives and APIs that comply with the best practices in the industry, 
while remaining flexible enough to be used in a wide range of use cases.

At the moment it implements the following RFCs (planning to get to full OIDC compliance):

- [x] OAuth 2.0 Authorization Code Grant (RFC 6749)
- [x] OAuth 2.0 Client Credentials Grant (RFC 6749)
- [x] OAuth 2.0 Refresh Token Grant (RFC 6749)
- [x] OIDC Hybrid Flow (OIDC Core 1.0)
- [x] PKCE Support (RFC 7636)
- [x] JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens (RFC 9068)

# Get Started 

## Basic Setup

First, you need to set up the database and API server. Then you can use the client to manage your services and applications.

```go
package main

import (
	"context"
	
	"go.authbricks.com/bricks/api"
	"go.authbricks.com/bricks/client"
	"go.authbricks.com/bricks/database"
)

func main() {
	// 1. Create database connection
	db, err := database.NewPostgres(context.Background(), "postgres://user:password@localhost:5432/db")
	if err != nil {
		panic(err)
	}
	
	// 2. Create API server
	a, err := api.New(db)
	if err != nil {
		panic(err)
	}
	
	// 3. Create client
	c := client.New(db)
	
	// Now you can use the client to manage your services and applications
	// See the Services section for examples
}
```

## Custom Routes

You can add custom routes to the API server using the `WithRoutes` option. This allows you to extend the API with your own endpoints and middleware.

```go
package main

import (
	"context"
	"net/http"
	
	"go.authbricks.com/bricks/api"
	"go.authbricks.com/bricks/database"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	db, err := database.NewPostgres(context.Background(), "postgres://user:password@localhost:5432/db")
	if err != nil {
		panic(err)
	}
	
	// Define custom routes
	routes := []api.Route{
		{
			Method: http.MethodGet,
			Path:   "/custom",
			Handler: echo.HandlerFunc(func(c echo.Context) error {
				return c.JSON(http.StatusTeapot, "custom route")
			}),
			Middlewares: []echo.MiddlewareFunc{},
		},
		{
			Method: http.MethodGet,
			Path:   "/custom/with/middleware",
			Handler: echo.HandlerFunc(func(c echo.Context) error {
				return c.JSON(http.StatusTeapot, "custom route with middleware")
			}),
			Middlewares: []echo.MiddlewareFunc{
				middleware.BasicAuth(func(username, password string, c echo.Context) (bool, error) {
					if username == "toni" && password == "hunter2" {
						return true, nil
					}
					return false, nil
				}),
			},
		},
	}
	
	// Create API server with custom routes
	a, err := api.New(db, ":8080",
		api.WithRoutes(routes),
	)
	if err != nil {
		panic(err)
	}
	
	a.ListenAndServe()
}
```

Each route can specify:
- `Method`: The HTTP method (GET, POST, etc.)
- `Path`: The URL path for the route
- `Handler`: The Echo handler function that processes the request
- `Middlewares`: Optional middleware functions to apply to the route

## Postgres 

Connect to a local postgres database, and start the API server on port 8080.

```go
package main

import (
	"context"
	
	"go.authbricks.com/bricks/api"
	"go.authbricks.com/bricks/database"
)

func main() {
	db, err := database.NewPostgres(context.Background(), "postgres://user:password@localhost:5432/db")
	if err != nil {
		panic(err)
	}
	
	a, err := api.New(db)
	if err != nil {
		panic(err)
	}
	
	a.ListenAndServe(":8080")
}
```

## MySQL

Connect to a local MySQL database, and start the API server on port 8080.

```go
package main

import (
	"context"
	
	"go.authbricks.com/bricks/api"
	"go.authbricks.com/bricks/database"
)

func main() {
	db, err := database.NewMySQL(context.Background(), "user:password@tcp(localhost:3306)/db")
	if err != nil {
		panic(err)
	}
	
	a, err := api.New(db)
	if err != nil {
		panic(err)
	}
	
	a.ListenAndServe(":8080")
}
```

## SQLite

Connect to a SQLite database, and start the API server on port 8080.

```go
package main 

import (
	"context"
	
	"go.authbricks.com/bricks/api"
	"go.authbricks.com/bricks/database"
)

func main() {
	db, err := database.NewSQLite(context.Background(), "file:file.db?_fk=1")
	if err != nil {
		panic(err)
	}
	
	a, err := api.New(db)
	if err != nil {
		panic(err)
	}
	
	a.ListenAndServe(":8080")
}
```
