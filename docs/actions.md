# Actions System

The Actions system in AuthBricks provides a flexible way to customize and extend the authentication flow. Actions are functions that can be executed at specific points in the authentication process, allowing for custom logic and modifications to the authentication flow.

## Action Structure

An Action is defined by the following structure:

```go
type Action struct {
    Name            string
    GrantType       string
    ServiceName     string
    ApplicationName string
    ActionFunc      ActionFunc
    Environment     map[string]any
}
```

### Fields

- `Name`: A unique identifier for the action
- `GrantType`: The OAuth2 grant type this action applies to (e.g., "authorization_code", "client_credentials")
- `ServiceName`: The specific service this action applies to
- `ApplicationName`: The specific application this action applies to
- `ActionFunc`: The function that implements the action's logic
- `Environment`: A map of environment variables and configuration available to the action

### Action Execution Scope

When creating an action, you can control when it executes by setting the `GrantType`, `ServiceName`, and `ApplicationName` fields:

1. **Global Actions**: Leave all three fields empty to create an action that executes for all contexts
2. **Grant Type Specific**: Set only `GrantType` to create an action that executes for a specific grant type across all services and applications
3. **Service Specific**: Set `ServiceName` to create an action that executes for a specific service across all grant types and applications
4. **Application Specific**: Set `ApplicationName` to create an action that executes for a specific application across all grant types and services
5. **Combined Scopes**: Set multiple fields to create an action that executes only when all specified fields match

For example:
- An action with `GrantType: "authorization_code"` will execute for all authorization code flows
- An action with `ServiceName: "my-service"` will execute for all operations involving "my-service"
- An action with both `GrantType: "authorization_code"` and `ServiceName: "my-service"` will only execute for authorization code flows in "my-service"

**Best Practice**: Be explicit about the scope of your actions by setting all relevant fields. This makes the behavior more predictable and easier to debug.

## Action Function

The action function has the following signature:

```go
type ActionFunc func(ctx context.Context, environment map[string]any, defaultClaims map[string]any) (map[string]any, error)
```

### Parameters

- `ctx`: The context for the action execution
- `environment`: A map containing environment variables and configuration
- `defaultClaims`: The default claims that would be included in the token

### Return Values

- `map[string]any`: The modified claims to be included in the token
- `error`: Any error that occurred during execution

## Access Token Action

The Access Token Action is a specific implementation that allows customization of the access token claims. This action is executed during the token issuance process and can modify the claims that will be included in the access token.

### Usage

To use the Access Token Action, you need to:

1. Define an action function that implements your custom logic
2. Create an Action instance with the appropriate configuration
3. Register the action with the authentication system

### Example

```go
func customAccessTokenAction(ctx context.Context, environment map[string]any, defaultClaims map[string]any) (map[string]any, error) {
    // Add custom claims
    defaultClaims["custom_claim"] = "value"
    
    // Modify existing claims
    if user, ok := environment["user"].(User); ok {
        defaultClaims["user_id"] = user.ID
    }
    
    return defaultClaims, nil
}

// Create the action
accessTokenAction := &Action{
    Name:        "custom_access_token",
    GrantType:   "authorization_code",
    ServiceName: "my_service",
    ActionFunc:  customAccessTokenAction,
    Environment: map[string]any{
        "user": currentUser,
    },
}
```

### Best Practices

1. **Keep Actions Focused**: Each action should have a single responsibility
2. **Handle Errors Gracefully**: Always return meaningful errors
3. **Validate Input**: Check the environment and default claims before modifying them
4. **Document Dependencies**: Clearly document any dependencies or requirements
5. **Test Thoroughly**: Write unit tests for your actions

### Security Considerations

1. **Validate Claims**: Ensure all claims are properly validated
2. **Protect Sensitive Data**: Don't include sensitive information in tokens
3. **Follow OAuth2 Standards**: Adhere to OAuth2 specifications for claim names and values
4. **Audit Actions**: Log important modifications to claims

## Integration

Actions can be integrated into the authentication flow through the API layer. The system will automatically execute relevant actions based on the grant type, service, and application context.

### Execution Order

1. System determines applicable actions based on context
2. Actions are executed in the order they were registered
3. Each action can modify the claims
4. Final claims are used to generate the access token

## Troubleshooting

Common issues and solutions:

1. **Action Not Executing**
   - Check grant type, service name, and application name match
   - Verify action registration
   - Check for errors in the action function

2. **Claims Not Modified**
   - Ensure action function returns modified claims
   - Check for nil or empty environment values
   - Verify claim modification logic

3. **Performance Issues**
   - Optimize action functions
   - Minimize database calls
   - Cache frequently used data 