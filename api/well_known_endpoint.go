package api

import (
	"net/http"

	"go.authbricks.com/bricks/ent"

	"github.com/labstack/echo/v4"
)

func (a *API) WellKnownHandler(_ *ent.Service) func(echo.Context) error {
	return func(c echo.Context) error {
		return c.JSON(http.StatusInternalServerError, "Not implemented")
	}
}
