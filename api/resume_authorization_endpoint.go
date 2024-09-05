package api

import (
	"context"
	"net/http"
	"time"

	"go.authbricks.com/bricks/ent"

	"github.com/labstack/echo/v4"
)

const (
	// SessionIDQueryParameter is the name of the query parameter
	// used to pass the session ID.
	SessionIDQueryParameter = "s"
)

type AuthorizationErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (a *API) ResumeAuthorizationHandler(service *ent.Service) func(echo.Context) error {
	return func(c echo.Context) error {
		// check if we have a session ID
		userCtx, err := a.getUserContext(c)
		if err != nil {
			a.Logger.Error("invalid request: failed to get user context", "error", err.Error())
			return c.JSON(http.StatusBadRequest, AuthorizationErrorResponse{
				Error:            ErrInvalidRequest,
				ErrorDescription: "invalid request: unauthorized",
			})
		}
		session, err := a.getSession(c.Request().Context(), userCtx.SessionID)
		if ent.IsNotFound(err) {
			a.Logger.Error("invalid request: session not found", "session_id", userCtx.SessionID, "service", service.Name)
			return c.JSON(http.StatusBadRequest, AuthorizationErrorResponse{
				Error:            ErrInvalidRequest,
				ErrorDescription: "invalid request: session not found",
			})
		}
		if err != nil {
			a.Logger.Error("server error: failed to get session", "session_id", userCtx.SessionID, "err", err.Error())
			return c.JSON(http.StatusInternalServerError, AuthorizationErrorResponse{
				Error:            ErrServerError,
				ErrorDescription: "server error: an internal error occurred",
			})
		}

		// check against a session valid for a separate service
		// do not leak this information to the client
		if session.ServiceName != service.Name {
			a.Logger.Error("invalid request: found session for a separate service", "session_id", userCtx.SessionID, "service", service.Name)
			return c.JSON(http.StatusBadRequest, AuthorizationErrorResponse{
				Error:            ErrInvalidRequest,
				ErrorDescription: "invalid request: session not found",
			})
		}

		loginConfig, err := service.QueryServiceLoginEndpointConfig().Only(c.Request().Context())
		if err != nil {
			a.Logger.Error("server error: failed to get login config", "service", service.Name, "error", err.Error())
			return c.JSON(http.StatusInternalServerError, AuthorizationErrorResponse{
				Error:            ErrServerError,
				ErrorDescription: "server error: an internal error occurred",
			})
		}

		// check if the session is expired
		if sessionIsExpired(session, time.Duration(loginConfig.SessionTimeout), time.Now()) {
			a.Logger.Error("invalid request: session expired", "session_id", userCtx.SessionID, "service", service.Name)
			return c.JSON(http.StatusBadRequest, AuthorizationErrorResponse{
				Error:            ErrInvalidRequest,
				ErrorDescription: "invalid request: session expired",
			})
		}

		// extract the payload from the session
		payload, err := session.QueryAuthorizationPayload().Only(c.Request().Context())
		if err != nil {
			a.Logger.Error("server error: failed to get authorization payload", "service", service.Name, "error", err.Error())
			return c.JSON(http.StatusInternalServerError, AuthorizationErrorResponse{
				Error:            ErrServerError,
				ErrorDescription: "server error: an internal error occurred",
			})
		}
		return a.authorizationFlow(c, service, payload)
	}
}

// getSession retrieves a session from the database.
func (a *API) getSession(ctx context.Context, id string) (*ent.Session, error) {
	return a.DB.EntClient.Session.Get(ctx, id)
}
