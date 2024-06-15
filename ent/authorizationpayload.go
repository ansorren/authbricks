// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"go.authbricks.com/bricks/ent/authorizationpayload"
	"go.authbricks.com/bricks/ent/session"
)

// AuthorizationPayload is the model entity for the AuthorizationPayload schema.
type AuthorizationPayload struct {
	config `json:"-"`
	// ID of the ent.
	ID string `json:"id"`
	// CodeChallenge holds the value of the "code_challenge" field.
	CodeChallenge string `json:"code_challenge"`
	// CodeChallengeMethod holds the value of the "code_challenge_method" field.
	CodeChallengeMethod string `json:"code_challenge_method"`
	// ClientID holds the value of the "client_id" field.
	ClientID string `json:"client_id"`
	// Nonce holds the value of the "nonce" field.
	Nonce string `json:"nonce"`
	// RedirectURI holds the value of the "redirect_uri" field.
	RedirectURI string `json:"redirect_uri"`
	// ResponseType holds the value of the "response_type" field.
	ResponseType string `json:"response_type"`
	// Scope holds the value of the "scope" field.
	Scope string `json:"scope"`
	// ServerName holds the value of the "server_name" field.
	ServerName string `json:"server_name"`
	// State holds the value of the "state" field.
	State string `json:"state"`
	// ResponseMode holds the value of the "response_mode" field.
	ResponseMode string `json:"response_mode"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the AuthorizationPayloadQuery when eager-loading is set.
	Edges                         AuthorizationPayloadEdges `json:"edges"`
	session_authorization_payload *string
	selectValues                  sql.SelectValues
}

// AuthorizationPayloadEdges holds the relations/edges for other nodes in the graph.
type AuthorizationPayloadEdges struct {
	// Session holds the value of the session edge.
	Session *Session `json:"session,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
}

// SessionOrErr returns the Session value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e AuthorizationPayloadEdges) SessionOrErr() (*Session, error) {
	if e.Session != nil {
		return e.Session, nil
	} else if e.loadedTypes[0] {
		return nil, &NotFoundError{label: session.Label}
	}
	return nil, &NotLoadedError{edge: "session"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*AuthorizationPayload) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case authorizationpayload.FieldID, authorizationpayload.FieldCodeChallenge, authorizationpayload.FieldCodeChallengeMethod, authorizationpayload.FieldClientID, authorizationpayload.FieldNonce, authorizationpayload.FieldRedirectURI, authorizationpayload.FieldResponseType, authorizationpayload.FieldScope, authorizationpayload.FieldServerName, authorizationpayload.FieldState, authorizationpayload.FieldResponseMode:
			values[i] = new(sql.NullString)
		case authorizationpayload.ForeignKeys[0]: // session_authorization_payload
			values[i] = new(sql.NullString)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the AuthorizationPayload fields.
func (ap *AuthorizationPayload) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case authorizationpayload.FieldID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value.Valid {
				ap.ID = value.String
			}
		case authorizationpayload.FieldCodeChallenge:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field code_challenge", values[i])
			} else if value.Valid {
				ap.CodeChallenge = value.String
			}
		case authorizationpayload.FieldCodeChallengeMethod:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field code_challenge_method", values[i])
			} else if value.Valid {
				ap.CodeChallengeMethod = value.String
			}
		case authorizationpayload.FieldClientID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field client_id", values[i])
			} else if value.Valid {
				ap.ClientID = value.String
			}
		case authorizationpayload.FieldNonce:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field nonce", values[i])
			} else if value.Valid {
				ap.Nonce = value.String
			}
		case authorizationpayload.FieldRedirectURI:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field redirect_uri", values[i])
			} else if value.Valid {
				ap.RedirectURI = value.String
			}
		case authorizationpayload.FieldResponseType:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field response_type", values[i])
			} else if value.Valid {
				ap.ResponseType = value.String
			}
		case authorizationpayload.FieldScope:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field scope", values[i])
			} else if value.Valid {
				ap.Scope = value.String
			}
		case authorizationpayload.FieldServerName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field server_name", values[i])
			} else if value.Valid {
				ap.ServerName = value.String
			}
		case authorizationpayload.FieldState:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field state", values[i])
			} else if value.Valid {
				ap.State = value.String
			}
		case authorizationpayload.FieldResponseMode:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field response_mode", values[i])
			} else if value.Valid {
				ap.ResponseMode = value.String
			}
		case authorizationpayload.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field session_authorization_payload", values[i])
			} else if value.Valid {
				ap.session_authorization_payload = new(string)
				*ap.session_authorization_payload = value.String
			}
		default:
			ap.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the AuthorizationPayload.
// This includes values selected through modifiers, order, etc.
func (ap *AuthorizationPayload) Value(name string) (ent.Value, error) {
	return ap.selectValues.Get(name)
}

// QuerySession queries the "session" edge of the AuthorizationPayload entity.
func (ap *AuthorizationPayload) QuerySession() *SessionQuery {
	return NewAuthorizationPayloadClient(ap.config).QuerySession(ap)
}

// Update returns a builder for updating this AuthorizationPayload.
// Note that you need to call AuthorizationPayload.Unwrap() before calling this method if this AuthorizationPayload
// was returned from a transaction, and the transaction was committed or rolled back.
func (ap *AuthorizationPayload) Update() *AuthorizationPayloadUpdateOne {
	return NewAuthorizationPayloadClient(ap.config).UpdateOne(ap)
}

// Unwrap unwraps the AuthorizationPayload entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (ap *AuthorizationPayload) Unwrap() *AuthorizationPayload {
	_tx, ok := ap.config.driver.(*txDriver)
	if !ok {
		panic("ent: AuthorizationPayload is not a transactional entity")
	}
	ap.config.driver = _tx.drv
	return ap
}

// String implements the fmt.Stringer.
func (ap *AuthorizationPayload) String() string {
	var builder strings.Builder
	builder.WriteString("AuthorizationPayload(")
	builder.WriteString(fmt.Sprintf("id=%v, ", ap.ID))
	builder.WriteString("code_challenge=")
	builder.WriteString(ap.CodeChallenge)
	builder.WriteString(", ")
	builder.WriteString("code_challenge_method=")
	builder.WriteString(ap.CodeChallengeMethod)
	builder.WriteString(", ")
	builder.WriteString("client_id=")
	builder.WriteString(ap.ClientID)
	builder.WriteString(", ")
	builder.WriteString("nonce=")
	builder.WriteString(ap.Nonce)
	builder.WriteString(", ")
	builder.WriteString("redirect_uri=")
	builder.WriteString(ap.RedirectURI)
	builder.WriteString(", ")
	builder.WriteString("response_type=")
	builder.WriteString(ap.ResponseType)
	builder.WriteString(", ")
	builder.WriteString("scope=")
	builder.WriteString(ap.Scope)
	builder.WriteString(", ")
	builder.WriteString("server_name=")
	builder.WriteString(ap.ServerName)
	builder.WriteString(", ")
	builder.WriteString("state=")
	builder.WriteString(ap.State)
	builder.WriteString(", ")
	builder.WriteString("response_mode=")
	builder.WriteString(ap.ResponseMode)
	builder.WriteByte(')')
	return builder.String()
}

// AuthorizationPayloads is a parsable slice of AuthorizationPayload.
type AuthorizationPayloads []*AuthorizationPayload