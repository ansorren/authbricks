---
weight: 11
title: Services
---

# Define a new Service

All the examples so far have simply started the API server on port 8080. The server does not actually have any endpoints yet. 
In this section, we will define a new service. 

In terms of OAuth / OIDC specifications, you can think of a `service` as your Authorization server.
For example, if your business needs to authenticate both your customers and your employees, you could define 
two different services called `customers` and `employees`

```go
serviceConfig := service.Config{
	Name: "customers",
	Scopes: []string{"read", "write"}, 
	GrantTypes: []string{"authorization_code"},
	ResponseTypes: []string{"code"},
}


svc, err := db.CreateOrUpdateService(context.Background(), serviceConfig)
if err != nil {
    panic(err)
}
```

# Define an Application
Once you have defined a service, you can create a new application (also known as OAuth Client) for that service.

```go
svc, err := db.GetService(context.Background(), "customers")
if err != nil {
    panic(err)
}

appConfig := application.Config{
    Name: "myapp",
    RedirectURIs: []string{"http://localhost:8080/callback"},
    GrantTypes: []string{"authorization_code"},
    ResponseTypes: []string{"code"},
    Scopes: []string{"read", "write"},
}

app, err := svc.CreateOrUpdateApplication(context.Background(), appConfig)
if err != nil {
    panic(err)
}
```

# Credentials

Once you have created an application, you can generate credentials for it.

```go

credentialsConfig := credentials.Config{
    ClientID: "myapp",
    ClientSecret: "mysecret",
}
creds, err := app.CreateCredentials(context.Background(), credentialsConfig)
if err != nil {
    panic(err)
}
```