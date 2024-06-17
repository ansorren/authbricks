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
    
    a, err := api.New(db)[kittens.md](kittens.md)
    if err != nil {
        panic(err)
    }
    
    a.ListenAndServe(":8080")
}
```
