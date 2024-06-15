---
weight: 10
title: AuthBricks
---

# AuthBricks

AuthBricks is a Go library for building Identity and Access Management solutions.
It aims to provide simple primitives and APIs that comply with the best practices in the industry, 
while remaining flexible enough to be used in a wide range of use cases.



# Get Started


## Postgres 

The following example shows how to create a new Postgres database connection and start the API server.
The server will then listen on port 8080. 

```go
package main

import (
	"context"
    
    "go.authbricks.com/bricks/api"
	"go.authbricks.com/bricks/db"
)

func main() {
	d, err := db.NewPostgres(context.Background(), "postgres://user:password@localhost:5432/db")
    if err != nil {
        panic(err)
    }
    
    a, err := api.New(d)
    if err != nil {
        panic(err)
    }
    
	a.ListenAndServe(":8080")
}
```





## MySQL
The following example shows how to create a new MySQL database connection and start the API server.

```go
package main

import (
    "context"
    
    "go.authbricks.com/bricks/api"
    "go.authbricks.com/bricks/db"
)

func main() {
    d, err := db.NewMySQL(context.Background(), "user:password@tcp(localhost:3306)/db")
    if err != nil {
        panic(err)
    }
    
    a, err := api.New(d)
    if err != nil {
        panic(err)
    }
    
    a.ListenAndServe(":8080")
}
```

## SQLite
The following example shows how to create a new SQLite database connection and start the API server.

```go
package main 

import (
    "context"
    
    "go.authbricks.com/bricks/api"
    "go.authbricks.com/bricks/db"
)

func main() {
    d, err := db.NewSQLite(context.Background(), "file.db")
    if err != nil {
        panic(err)
    }
    
    a, err := api.New(d)
    if err != nil {
        panic(err)
    }
    
    a.ListenAndServe(":8080")
}
```
