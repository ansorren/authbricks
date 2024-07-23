package api

import (
	"crypto"
	"net/http"

	abcrypto "go.authbricks.com/bricks/crypto"
	"go.authbricks.com/bricks/ent"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

type JWKSErrorResponse struct {
	Error string `json:"error"`
}

func (a *API) JWKSHandler(service *ent.Service) func(echo.Context) error {
	return func(c echo.Context) error {
		ks, err := service.QueryKeySet().Only(c.Request().Context())
		if err != nil {
			a.Logger.Error("Failed to query key set", "error", err.Error(), "service", service.Name)
			return c.JSON(http.StatusInternalServerError, JWKSErrorResponse{
				Error: "Failed to query key set",
			})
		}

		signingKeys, err := ks.QuerySigningKeys().All(c.Request().Context())
		if err != nil {
			a.Logger.Error("Failed to query signing keys", "error", err.Error(), "service", service.Name)
			return c.JSON(http.StatusInternalServerError, JWKSErrorResponse{
				Error: "Failed to query signing keys",
			})
		}
		publicKeys, err := convertToPublicKeys(signingKeys)
		if err != nil {
			a.Logger.Error("Failed to convert to public keys", "error", err.Error(), "service", service.Name)
			return c.JSON(http.StatusInternalServerError, JWKSErrorResponse{
				Error: "Failed to convert to public keys",
			})
		}

		jwks, err := abcrypto.NewKeySet(publicKeys)
		if err != nil {
			a.Logger.Error("Failed to instantiate key set", "error", err.Error(), "service", service.Name)
			return c.JSON(http.StatusInternalServerError, JWKSErrorResponse{
				Error: "Failed to create key set",
			})
		}

		return c.JSON(http.StatusOK, jwks)
	}
}

// convertToPublicKeys is a helper function to convert the given signing keys to a slice of crypto.PublicKey.
// Note: only RSA keys are supported at the moment.
func convertToPublicKeys(signingKeys []*ent.SigningKey) ([]crypto.PublicKey, error) {
	var ret []crypto.PublicKey
	for _, k := range signingKeys {
		rsaKey, err := abcrypto.GetRSAKeyFromPEM([]byte(k.Key))
		if err != nil {
			return nil, errors.Wrapf(err, "unable to get RSA key from PEM")
		}
		ret = append(ret, rsaKey.Public)
	}
	return ret, nil
}
