package api

import (
	"bytes"
	_ "embed"
	"html/template"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

//go:embed html/authorization_failed.html.tpl
var authorizationFailed string

type AuthorizationFailedData struct {
	ErrorTitle       string
	ErrorDescription string
}

// renderAuthFailedTemplate renders the authorization failed template.
func renderAuthFailedTemplate(errorTitle string, errorDescription error) (string, error) {
	tpl := template.New("tpl")
	tpl, err := tpl.Parse(authorizationFailed)
	if err != nil {
		// this should never happen
		return "", errors.Wrapf(err, "unable to parse template")
	}

	var buf bytes.Buffer
	data := AuthorizationFailedData{
		ErrorTitle:       errorTitle,
		ErrorDescription: errorDescription.Error(),
	}
	err = tpl.Execute(&buf, &data)
	if err != nil {
		return "", errors.Wrapf(err, "unable to execute template")
	}

	return buf.String(), nil
}

// serveAuthFailedTemplate serves the authorization failed template.
func (a *API) serveAuthFailedTemplate(c echo.Context, errorTitle string, errorDescription error) error {
	tpl, err := renderAuthFailedTemplate(errorTitle, errorDescription)
	type errorMessage struct {
		Error string `json:"error"`
	}
	if err != nil {
		return c.JSON(http.StatusInternalServerError, errorMessage{
			Error: errors.Wrapf(err, "unable to render template").Error(),
		})
	}

	return c.HTML(http.StatusBadRequest, tpl)
}
