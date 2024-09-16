package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

const userContextSessionKey = "user_context"

// UserContext is the context of the user.
type UserContext struct {
	SessionID     string
	ServiceName   string
	Subject       string
	Authenticated bool
	authTime      time.Time
}

// IsAuthenticated returns true if the user is authenticated.
func (u UserContext) IsAuthenticated() bool {
	return u.Authenticated
}

// AuthTime returns the time at which the user was authenticated.
func (u UserContext) AuthTime() time.Time {
	return u.authTime
}

// getUserContext returns the user context from the session.
func (a *API) getUserContext(c echo.Context) (UserContext, error) {
	sess, err := session.Get(SessionAuthenticate, c)
	if err != nil {
		a.Logger.Error("cannot get session", "error", err.Error())
		return UserContext{
			Authenticated: false,
		}, errors.Wrapf(err, "unable to get session")
	}
	fmt.Println("cookies received", c.Request().Cookies())
	fmt.Println(sess.Values)
	u, ok := sess.Values[userContextSessionKey]
	if !ok {
		return UserContext{
			Authenticated: false,
		}, errors.New("unable to get user context from session")
	}

	userContext, ok := u.(UserContext)
	if !ok {
		return UserContext{
			Authenticated: false,
		}, errors.New("unable to convert user context from session")
	}

	return userContext, nil
}

// setUserContext sets the user context in the session.
func (a *API) setUserContext(c echo.Context, userContext UserContext) error {
	sess, err := session.Get(SessionAuthenticate, c)
	if err != nil {
		a.Logger.Error("cannot get session", "error", err.Error())
		return errors.Wrapf(err, "unable to get session")
	}

	sess.Options = &sessions.Options{
		MaxAge:   86400,
		Secure:   false, // FIXME: Don't hardcode
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	}

	sess.Values[userContextSessionKey] = userContext

	err = sess.Save(c.Request(), c.Response())
	if err != nil {
		a.Logger.Error("cannot save session", "error", err.Error())
		return errors.Wrapf(err, "unable to save session")
	}

	return nil
}
