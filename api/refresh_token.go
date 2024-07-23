package api

import (
	"fmt"

	"go.authbricks.com/bricks/ent"

	"github.com/labstack/echo/v4"
)

func (a *API) RefreshTokenFlow(c echo.Context, payload TokenPayload, service *ent.Service) error {
	return fmt.Errorf("not implemented")
}
