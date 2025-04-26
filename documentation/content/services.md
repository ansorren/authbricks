---
weight: 11
title: Services
---

# Define a new Service

All the examples so far have simply started the API server on port 8080. The server does not actually have any endpoints yet. 
In this section, we will define a new service. 

In terms of OAuth / OIDC specifications, you can think of a `service` as your Authorization server.
For example, if your business needs to authenticate both your customers and your employees, you could define 
two different services called `customers` and `employees`.

```go
package main

import (
    "context"
    "crypto/rsa"
    "crypto/rand"
    
    "go.authbricks.com/bricks/api"
    "go.authbricks.com/bricks/client"
    "go.authbricks.com/bricks/config"
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
    
    // 4. Generate RSA key for signing
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        panic(err)
    }
    
    // 5. Create service configuration
    serviceConfig := config.Service{
        Name: "customers",
        Identifier: "customers",
        Description: "Service for authenticating customers",
        ServiceMetadata: config.ServiceMetadata{
            "version": "1.0.0",
            "environment": "production",
        },
        AllowedClientMetadata: []string{"logo_uri", "client_uri", "policy_uri"},
        Scopes: []string{"openid", "profile", "email", "read", "write"},
        GrantTypes: []string{
            config.GrantTypeAuthorizationCode,
            config.GrantTypeClientCredentials,
            config.GrantTypeRefreshToken,
        },
        ResponseTypes: []string{
            config.ResponseTypeCode,
            config.ResponseTypeIDToken,
            config.ResponseTypeCodeIDToken,
        },
        AuthorizationEndpoint: config.AuthorizationEndpoint{
            Enabled: true,
        },
        TokenEndpoint: config.TokenEndpoint{
            Enabled: true,
        },
        UserInfoEndpoint: config.UserInfoEndpoint{
            Enabled: true,
        },
        JWKSEndpoint: config.JWKSEndpoint{
            Enabled: true,
        },
        WellKnownEndpoint: config.WellKnownEndpoint{
            Enabled: true,
        },
        LoginEndpoint: config.LoginEndpoint{
            Enabled: true,
        },
        Connection: config.Connection{
            EmailPassword: &config.EmailPasswordConnection{
                Enabled: true,
            },
            OIDC: []config.OIDCConnection{
                {
                    Name: "google",
                    Enabled: true,
                    ClientID: "your-google-client-id",
                    ClientSecret: "your-google-client-secret",
                    Scopes: []string{"openid", "profile", "email"},
                    RedirectURI: "http://localhost:8080/callback",
                    WellKnownEndpoint: "https://accounts.google.com/.well-known/openid-configuration",
                },
                {
                    Name: "github",
                    Enabled: true,
                    ClientID: "your-github-client-id",
                    ClientSecret: "your-github-client-secret",
                    Scopes: []string{"read:user", "user:email"},
                    RedirectURI: "http://localhost:8080/callback",
                    WellKnownEndpoint: "https://github.com/.well-known/openid-configuration",
                },
            },
        },
        Keys: []crypto.PrivateKey{privateKey},
    }
    
    // 6. Create service using the client
    svc, err := c.CreateOrUpdateService(context.Background(), serviceConfig)
    if err != nil {
        panic(err)
    }
    
    // 7. Start the API server
    a.ListenAndServe(":8080")
}
```

# Define an Application
Once you have defined a service, you can create a new application (also known as OAuth Client) for that service.

```go
package main

import (
    "context"
    
    "go.authbricks.com/bricks/api"
    "go.authbricks.com/bricks/client"
    "go.authbricks.com/bricks/config"
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
    
    // 4. Get service
    svc, err := c.GetService(context.Background(), "customers")
    if err != nil {
        panic(err)
    }
    
    // 5. Create application configuration
    appConfig := config.Application{
        Name: "myapp",
        Service: "customers",
        Description: "My OAuth2/OIDC Application",
        Public: false,
        RedirectURIs: []string{
            "http://localhost:8080/callback",
            "https://myapp.com/callback",
        },
        ResponseTypes: []string{
            config.ResponseTypeCode,
            config.ResponseTypeIDToken,
            config.ResponseTypeCodeIDToken,
        },
        GrantTypes: []string{
            config.GrantTypeAuthorizationCode,
            config.GrantTypeRefreshToken,
        },
        PKCERequired: true,
        S256CodeChallengeMethodRequired: true,
        AllowedAuthenticationMethods: []string{"client_secret_basic", "client_secret_post"},
        Scopes: []string{"openid", "profile", "email", "read", "write"},
    }
    
    // 6. Create application using the client
    app, err := c.CreateOrUpdateApplication(context.Background(), appConfig)
    if err != nil {
        panic(err)
    }
    
    // 7. Start the API server
    a.ListenAndServe(":8080")
}
```

# Credentials

Once you have created an application, you can generate credentials for it.

```go
package main

import (
    "context"
    
    "go.authbricks.com/bricks/api"
    "go.authbricks.com/bricks/client"
    "go.authbricks.com/bricks/config"
    "go.authbricks.com/bricks/database"
    "go.authbricks.com/bricks/crypto"
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
    
    // 4. Get application
    app, err := c.GetApplication(context.Background(), "myapp")
    if err != nil {
        panic(err)
    }
    
    // 5. Create credentials configuration
    credentialsConfig := config.Credentials{
        ClientID: crypto.GenerateClientID(),
        ClientSecret: crypto.GenerateClientSecret(),
    }
    
    // 6. Create credentials using the client
    creds, err := c.CreateOrUpdateCredentials(context.Background(), credentialsConfig)
    if err != nil {
        panic(err)
    }
    
    // 7. Start the API server
    a.ListenAndServe(":8080")
}
```