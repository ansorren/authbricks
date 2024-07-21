package api

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// HealthSuccessResponse is the response returned by the health handler.
type HealthSuccessResponse struct {
	Status string `json:"status"`
}

// HealthHandler is used to return the health status of the API.
func (a *API) HealthHandler() func(echo.Context) error {
	return func(c echo.Context) error {
		return c.JSON(http.StatusOK, HealthSuccessResponse{
			Status: "OK",
		})
	}
}

