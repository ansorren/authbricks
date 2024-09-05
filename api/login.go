package api

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"net/http"

	"go.authbricks.com/bricks/ent"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

//go:embed html/login_page.html.tpl
var loginPageTemplate string

type GetLoginErrorResponse struct {
	Error string `json:"error"`
}

// emailPasswordForm is the HTML form for email/password connectors.
func emailPasswordForm(csrfToken string) string {
	return fmt.Sprintf(`
    <form id="loginForm">
        <label for="username">Email:</label>
        <input type="text" id="username" placeholder="Enter Email" name="username" required autocomplete="on">
        <label for="password">Password:</label>
		<input type="hidden" id="csrf_token" name="csrf_token" value="%s">
        <input type="password" id="password" placeholder="Enter Password" name="password" required autocomplete="on">
        <button type="submit">Login</button>
    </form>
`, csrfToken)
}

// forgotPasswordForm is the HTML form for forgot password.
var forgotPasswordForm = `
	<div class="forgot-password">
		<a href="#">Forgot password?</a>
	</div>
`

// oidcForm returns the HTML form for OIDC connectors.
func oidcForm(connectors []Connector) string {
	var buttons string
	for _, conn := range connectors {
		buttons += fmt.Sprintf(`
		<div/>
			<button type="submit" id="oidc-login-btn-%s">Login with OIDC</button>
		</div>
`, conn.ID())
	}
	return buttons
}

func (a *API) GETLoginHandler(service *ent.Service) func(echo.Context) error {
	return func(c echo.Context) error {
		valid := a.validateSessionID(c)
		if !valid {
			return a.setSessionIDAndRedirect(c)
		}
		csrfToken, ok := c.Get(middleware.DefaultCSRFConfig.ContextKey).(string)
		if !ok {
			return c.JSON(http.StatusInternalServerError, GetLoginErrorResponse{
				Error: "server error: unable to get CSRF token",
			})
		}

		if csrfToken == "" {
			return c.JSON(http.StatusInternalServerError, GetLoginErrorResponse{
				Error: "server error: CSRF token is empty",
			})
		}

		t, err := template.New("login_page.html.tpl").
			Funcs(template.FuncMap{
				"email_password_connector": func() (template.HTML, error) {
					connectors, err := a.getAvailableConnectors(c.Request().Context(), service)
					if err != nil {
						return "", fmt.Errorf("server error: unable to get available connectors")
					}
					for _, conn := range connectors {
						if conn.Type() == connectorTypeEmailPassword {
							csrfToken, ok := c.Get(middleware.DefaultCSRFConfig.ContextKey).(string)
							if !ok {
								return "", fmt.Errorf("server error: unable to get CSRF token")
							}
							return template.HTML(emailPasswordForm(csrfToken)), nil
						}
					}
					return "", nil
				},
				"oidc_connectors": func() template.HTML {
					connectors, err := a.getAvailableConnectors(c.Request().Context(), service)
					if err != nil {
						return "server error: unable to get available connectors"
					}
					var oidcConnectors []Connector
					for _, conn := range connectors {
						if conn.Type() == connectorTypeOIDC {
							oidcConnectors = append(oidcConnectors, conn)
						}
					}
					return template.HTML(oidcForm(oidcConnectors))
				},
				"forgot_password": func() template.HTML {
					connectors, err := a.getAvailableConnectors(c.Request().Context(), service)
					if err != nil {
						return "server error: unable to get available connectors"
					}
					for _, conn := range connectors {
						if conn.Type() == connectorTypeEmailPassword {
							return template.HTML(forgotPasswordForm)
						}
					}
					return ""
				},
			}).Parse(loginPageTemplate)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, GetLoginErrorResponse{
				Error: "server error: unable to parse login page template",
			})
		}

		buf := new(bytes.Buffer)
		err = t.Execute(buf, nil)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, GetLoginErrorResponse{
				Error: "server error: unable to execute login page template",
			})
		}

		return c.HTML(http.StatusOK, buf.String())
	}
}

// validateSessionID validates the session ID.
func (a *API) validateSessionID(c echo.Context) bool {
	id := c.QueryParam(SessionIDQueryParameter)
	// assert that the id is a valid uuid
	_, err := uuid.Parse(id)
	if err == nil {
		// got a valid UUID set, nothing to do
		return true
	}
	return false
}

// setSessionIDAndRedirect sets a new session id and redirects to the login page.
func (a *API) setSessionIDAndRedirect(c echo.Context) error {
	// redirect to the login page
	// by generating a new session id
	// set the new id as a query parameter
	id := uuid.New().String()
	u := c.Request().URL
	q := u.Query()
	q.Set(SessionIDQueryParameter, id)
	u.RawQuery = q.Encode()
	return c.Redirect(http.StatusFound, u.String())
}

// POSTLoginErrorResponse is a struct to hold the error response when
// a POST request to the login endpoint fails.
type POSTLoginErrorResponse struct {
	Error string `json:"error"`
}

func (a *API) POSTLoginHandler(service *ent.Service) func(echo.Context) error {
	return func(c echo.Context) error {
		sessionID := c.QueryParam(SessionIDQueryParameter)
		if sessionID == "" {
			a.Logger.Error("invalid request: missing session ID", "service", service.Name)
			return c.JSON(http.StatusBadRequest, AuthorizationErrorResponse{
				Error:            ErrInvalidRequest,
				ErrorDescription: "invalid request: missing session ID",
			})
		}
		connectors, err := a.getAvailableConnectors(c.Request().Context(), service)
		if err != nil {
			a.Logger.Error("server error: unable to get available connections", "error", err)
			return c.JSON(http.StatusInternalServerError, POSTLoginErrorResponse{
				Error: "server error: an internal error occurred",
			})
		}
		emailPass := Connectors(connectors).EmailPassword()
		if emailPass == nil {
			return c.JSON(http.StatusBadRequest, POSTLoginErrorResponse{
				Error: "invalid request: email/password connection not set for the service",
			})
		}
		userCtx, err := emailPass.Connect(c, service, c.Request().Body)
		if err != nil {
			return c.JSON(http.StatusBadRequest, POSTLoginErrorResponse{
				Error: err.Error(),
			})
		}
		// set the user context in the session
		userCtx.SessionID = sessionID
		err = a.setUserContext(c, userCtx)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, POSTLoginErrorResponse{
				Error: "server error: unable to set session user context",
			})
		}

		authConfig, err := service.QueryServiceAuthorizationEndpointConfig().Only(c.Request().Context())
		if err != nil {
			a.Logger.Error("server error: unable to get service authorization endpoint config", "service", service, "error", err)
			return c.JSON(http.StatusInternalServerError, POSTLoginErrorResponse{
				Error: "server error: unable to get service authorization endpoint config",
			})
		}

		e := sanitiseEndpoint(authConfig.Endpoint, a.BaseURL)
		resumeEndpoint := fmt.Sprintf("%s/resume", e)

		return c.Redirect(http.StatusFound, resumeEndpoint)
	}
}
