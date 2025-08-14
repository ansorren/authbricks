---
weight: 12
title: Configuration
---

# Configuration Patterns

AuthBricks provides flexible configuration patterns to help you set up services, applications, and credentials. This section covers the different approaches available.

## Functional Options Pattern

AuthBricks implements the functional options pattern, which provides a clean and extensible way to configure components. This pattern offers several advantages:

- **Readability**: Options clearly describe what they configure
- **Flexibility**: Only specify the options you need
- **Extensibility**: New options can be added without breaking existing code
- **Type Safety**: Compile-time checking of configuration parameters

### Service Configuration

The service functional options are available in the `go.authbricks.com/bricks/config/options/service` package:

```go
import "go.authbricks.com/bricks/config/options/service"

serviceConfig := service.New(
    service.WithName("my-service"),
    service.WithIdentifier("my-service-id"),
    service.WithDescription("My OAuth2 service"),
    service.WithScopes("openid", "profile", "email"),
    service.WithGrantTypes(
        config.GrantTypeAuthorizationCode,
        config.GrantTypeRefreshToken,
    ),
    service.WithResponseTypes(config.ResponseTypeCode),
    // Add more options as needed
)
```

Available service options:
- `WithName(string)` - Set the service name
- `WithIdentifier(string)` - Set the service identifier
- `WithDescription(string)` - Set the service description
- `WithServiceMetadata(ServiceMetadata)` - Set all service metadata
- `WithServiceMetadataEntry(key, value string)` - Add a single metadata entry
- `WithAllowedClientMetadata(...string)` - Set allowed client metadata fields
- `WithAllowedClientMetadataEntry(string)` - Add a single allowed metadata field
- `WithScopes(...string)` - Set all supported scopes
- `WithScope(string)` - Add a single scope
- `WithGrantTypes(...string)` - Set all supported grant types
- `WithGrantType(string)` - Add a single grant type
- `WithResponseTypes(...string)` - Set all supported response types
- `WithResponseType(string)` - Add a single response type
- `WithAuthorizationEndpoint(AuthorizationEndpoint)` - Configure authorization endpoint
- `WithIntrospectionEndpoint(IntrospectionEndpoint)` - Configure introspection endpoint
- `WithTokenEndpoint(TokenEndpoint)` - Configure token endpoint
- `WithUserInfoEndpoint(UserInfoEndpoint)` - Configure userinfo endpoint
- `WithJWKSEndpoint(JWKSEndpoint)` - Configure JWKS endpoint
- `WithWellKnownEndpoint(WellKnownEndpoint)` - Configure well-known endpoint
- `WithLoginEndpoint(LoginEndpoint)` - Configure login endpoint
- `WithConnection(Connection)` - Set connection configuration
- `WithKeys(...crypto.PrivateKey)` - Set all signing keys
- `WithKey(crypto.PrivateKey)` - Add a single signing key

### Application Configuration

The application functional options are available in the `go.authbricks.com/bricks/config/options/application` package:

```go
import "go.authbricks.com/bricks/config/options/application"

appConfig := application.New(
    application.WithName("my-app"),
    application.WithService("my-service"),
    application.WithDescription("My OAuth2 application"),
    application.WithPublic(false),
    application.WithRedirectURIs("https://example.com/callback"),
    application.WithPKCERequired(true),
    // Add more options as needed
)
```

Available application options:
- `WithName(string)` - Set the application name
- `WithService(string)` - Set the parent service name
- `WithDescription(string)` - Set the application description
- `WithPublic(bool)` - Set whether the application is public (no client secret)
- `WithRedirectURIs(...string)` - Set all redirect URIs
- `WithRedirectURI(string)` - Add a single redirect URI
- `WithResponseTypes(...string)` - Set all supported response types
- `WithResponseType(string)` - Add a single response type
- `WithGrantTypes(...string)` - Set all supported grant types
- `WithGrantType(string)` - Add a single grant type
- `WithPKCERequired(bool)` - Set whether PKCE is required
- `WithS256CodeChallengeMethodRequired(bool)` - Set whether S256 PKCE method is required
- `WithAllowedAuthenticationMethods(...string)` - Set all allowed authentication methods
- `WithAllowedAuthenticationMethod(string)` - Add a single authentication method
- `WithScopes(...string)` - Set all allowed scopes
- `WithScope(string)` - Add a single scope

### Credentials Configuration

The credentials functional options are available in the `go.authbricks.com/bricks/config/options/credentials` package:

```go
import "go.authbricks.com/bricks/config/options/credentials"

credentialsConfig := credentials.New(
    credentials.WithApplication("my-app"),
    credentials.WithClientID("my-client-id"),
    credentials.WithClientSecret("my-client-secret"),
)
```

Available credentials options:
- `WithApplication(string)` - Set the application name
- `WithClientID(string)` - Set the OAuth2 client ID
- `WithClientSecret(string)` - Set the OAuth2 client secret

### API Configuration

The API functional options are available directly in the `go.authbricks.com/bricks/api` package:

```go
import (
    "context"
    
    "go.authbricks.com/bricks/api"
    "go.authbricks.com/bricks/database"
    "github.com/hashicorp/go-hclog"
)

func main() {
    db, err := database.NewPostgres(context.Background(), "postgres://user:password@localhost:5432/db")
    if err != nil {
        panic(err)
    }
    
    // Create API server with functional options
    a, err := api.New(db, ":8080",
        api.WithLogger(hclog.Default()),
        api.WithBaseURL("https://api.example.com"),
        api.WithTLSEnabled(true),
        api.WithCertificateFilePath("/path/to/cert.pem"),
        api.WithKeyFilePath("/path/to/key.pem"),
    )
    if err != nil {
        panic(err)
    }
    
    a.ListenAndServe()
}
```

Available API options:
- `WithLogger(hclog.Logger)` - Set custom logger
- `WithBaseURL(string)` - Set the base URL for the API
- `WithTLSEnabled(bool)` - Enable/disable TLS
- `WithCertificate([]byte)` - Set TLS certificate directly
- `WithKey([]byte)` - Set TLS private key directly
- `WithCertificateFilePath(string)` - Set path to TLS certificate file
- `WithKeyFilePath(string)` - Set path to TLS private key file
- `WithRoutes([]Route)` - Add custom routes
- `WithAccessTokenActions([]Action)` - Set access token actions
- `WithIDTokenActions([]Action)` - Set ID token actions

## Direct Configuration

For cases where you prefer or need direct struct initialization, you can still use the config structs directly:

```go
import "go.authbricks.com/bricks/config"

func main() {
serviceConfig := config.Service{
Name:        "my-service",
Identifier:  "my-service-id",
Description: "My OAuth2 service",
Scopes:      []string{"openid", "profile", "email"},
GrantTypes: []string{
        config.GrantTypeAuthorizationCode,
		config.GrantTypeRefreshToken,
    },
    ResponseTypes: []string{config.ResponseTypeCode},
    // ... other fields
    }
}
```
