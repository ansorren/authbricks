package api

import "github.com/labstack/echo/v4"

// Route is a custom route that can be added to the server.
type Route struct {
	Method      string
	Path        string
	Handler     echo.HandlerFunc
	Middlewares []echo.MiddlewareFunc
}

// pathUnique returns true if the given path is unique in the given routes
// (i.e. it's only present once).
func pathUnique(path string, routes []Route) bool {
	count := 0
	for _, route := range routes {
		if route.Path == path {
			count++
		}
	}

	if count == 1 {
		return true
	}
	return false
}
