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
    "go.authbricks.com/bricks/config/options/service"
    "go.authbricks.com/bricks/database"
    "github.com/hashicorp/go-hclog"
)

func main() {
    ctx := context.Background()
    
    // 1. Create database connection
    db, err := database.NewPostgres(ctx, "postgres://user:password@localhost:5432/db")
    if err != nil {
        panic(err)
    }
    
    // 2. Create API server with functional options
    a, err := api.New(db, ":8080",
        api.WithLogger(hclog.Default()),
        api.WithBaseURL("https://api.example.com"),
    )
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
    
    // 5. Create service configuration using functional options
    serviceConfig := service.New(
        service.WithName("customers"),
        service.WithIdentifier("customers"),
        service.WithDescription("Service for authenticating customers"),
        service.WithServiceMetadataEntry("version", "1.0.0"),
        service.WithServiceMetadataEntry("environment", "production"),
        service.WithAllowedClientMetadata("logo_uri", "client_uri", "policy_uri"),
        service.WithScopes("openid", "profile", "email", "read", "write"),
        service.WithGrantTypes(
            config.GrantTypeAuthorizationCode,
            config.GrantTypeClientCredentials,
            config.GrantTypeRefreshToken,
        ),
        service.WithResponseTypes(
            config.ResponseTypeCode,
            config.ResponseTypeIDToken,
            config.ResponseTypeCodeIDToken,
        ),
        service.WithAuthorizationEndpoint(config.AuthorizationEndpoint{
            Enabled: true,
        }),
        service.WithTokenEndpoint(config.TokenEndpoint{
            Enabled: true,
        }),
        service.WithUserInfoEndpoint(config.UserInfoEndpoint{
            Enabled: true,
        }),
        service.WithJWKSEndpoint(config.JWKSEndpoint{
            Enabled: true,
        }),
        service.WithWellKnownEndpoint(config.WellKnownEndpoint{
            Enabled: true,
        }),
        service.WithLoginEndpoint(config.LoginEndpoint{
            Enabled: true,
        }),
        service.WithConnection(config.Connection{
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
        }),
        service.WithKey(privateKey),
    )
    
    // 6. Create service using the client
    svc, err := c.CreateOrUpdateService(context.Background(), serviceConfig)
    if err != nil {
        panic(err)
    }
    
    // 7. Start the API server
    if err := a.Run(ctx); err != nil {
        panic(err)
    }
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
    "go.authbricks.com/bricks/config/options/application"
    "go.authbricks.com/bricks/database"
    "github.com/hashicorp/go-hclog"
)

func main() {
    ctx := context.Background()
    
    // 1. Create database connection
    db, err := database.NewPostgres(ctx, "postgres://user:password@localhost:5432/db")
    if err != nil {
        panic(err)
    }
    
    // 2. Create API server with functional options
    a, err := api.New(db, ":8080",
        api.WithLogger(hclog.Default()),
        api.WithBaseURL("https://api.example.com"),
    )
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
    
    // 5. Create application configuration using functional options
    appConfig := application.New(
        application.WithName("myapp"),
        application.WithService("customers"),
        application.WithDescription("My OAuth2/OIDC Application"),
        application.WithPublic(false),
        application.WithRedirectURIs(
            "http://localhost:8080/callback",
            "https://myapp.com/callback",
        ),
        application.WithResponseTypes(
            config.ResponseTypeCode,
            config.ResponseTypeIDToken,
            config.ResponseTypeCodeIDToken,
        ),
        application.WithGrantTypes(
            config.GrantTypeAuthorizationCode,
            config.GrantTypeRefreshToken,
        ),
        application.WithPKCERequired(true),
        application.WithS256CodeChallengeMethodRequired(true),
        application.WithAllowedAuthenticationMethods("client_secret_basic", "client_secret_post"),
        application.WithScopes("openid", "profile", "email", "read", "write"),
    )
    
    // 6. Create application using the client
    app, err := c.CreateOrUpdateApplication(context.Background(), appConfig)
    if err != nil {
        panic(err)
    }
    
    // 7. Start the API server
    if err := a.Run(ctx); err != nil {
        panic(err)
    }
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
    "go.authbricks.com/bricks/config/options/credentials"
    "go.authbricks.com/bricks/crypto"
    "go.authbricks.com/bricks/database"
    "github.com/hashicorp/go-hclog"
)

func main() {
    ctx := context.Background()
    
    // 1. Create database connection
    db, err := database.NewPostgres(ctx, "postgres://user:password@localhost:5432/db")
    if err != nil {
        panic(err)
    }
    
    // 2. Create API server with functional options
    a, err := api.New(db, ":8080",
        api.WithLogger(hclog.Default()),
        api.WithBaseURL("https://api.example.com"),
    )
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
    
    // 5. Create credentials configuration using functional options
    credentialsConfig := credentials.New(
        credentials.WithApplication("myapp"),
        credentials.WithClientID(crypto.GenerateClientID()),
        credentials.WithClientSecret(crypto.GenerateClientSecret()),
    )
    
    // 6. Create credentials using the client
    creds, err := c.CreateOrUpdateCredentials(context.Background(), credentialsConfig)
    if err != nil {
        panic(err)
    }
    
    // 7. Start the API server
    if err := a.Run(ctx); err != nil {
        panic(err)
    }
}
```