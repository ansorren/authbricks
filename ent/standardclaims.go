// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"go.authbricks.com/bricks/ent/standardclaims"
	"go.authbricks.com/bricks/ent/user"
)

// StandardClaims is the model entity for the StandardClaims schema.
type StandardClaims struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// Subject holds the value of the "subject" field.
	Subject string `json:"sub"`
	// Name holds the value of the "name" field.
	Name string `json:"name,omitempty"`
	// GivenName holds the value of the "given_name" field.
	GivenName string `json:"given_name,omitempty"`
	// FamilyName holds the value of the "family_name" field.
	FamilyName string `json:"family_name,omitempty"`
	// MiddleName holds the value of the "middle_name" field.
	MiddleName string `json:"middle_name,omitempty"`
	// Nickname holds the value of the "nickname" field.
	Nickname string `json:"nickname,omitempty"`
	// PreferredUsername holds the value of the "preferred_username" field.
	PreferredUsername string `json:"preferred_username,omitempty"`
	// Profile holds the value of the "profile" field.
	Profile string `json:"profile,omitempty"`
	// Picture holds the value of the "picture" field.
	Picture string `json:"picture,omitempty"`
	// Website holds the value of the "website" field.
	Website string `json:"website,omitempty"`
	// Email holds the value of the "email" field.
	Email string `json:"email,omitempty"`
	// EmailVerified holds the value of the "email_verified" field.
	EmailVerified bool `json:"email_verified,omitempty"`
	// Gender holds the value of the "gender" field.
	Gender string `json:"gender,omitempty"`
	// Birthdate holds the value of the "birthdate" field.
	Birthdate string `json:"birthdate,omitempty"`
	// Zoneinfo holds the value of the "zoneinfo" field.
	Zoneinfo string `json:"zoneinfo,omitempty"`
	// Locale holds the value of the "locale" field.
	Locale string `json:"locale,omitempty"`
	// PhoneNumber holds the value of the "phone_number" field.
	PhoneNumber string `json:"phone_number,omitempty"`
	// PhoneNumberVerified holds the value of the "phone_number_verified" field.
	PhoneNumberVerified bool `json:"phone_number_verified,omitempty"`
	// Address holds the value of the "address" field.
	Address string `json:"address,omitempty"`
	// UpdatedAt holds the value of the "updated_at" field.
	UpdatedAt int64 `json:"updated_at,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the StandardClaimsQuery when eager-loading is set.
	Edges                StandardClaimsEdges `json:"edges"`
	user_standard_claims *string
	selectValues         sql.SelectValues
}

// StandardClaimsEdges holds the relations/edges for other nodes in the graph.
type StandardClaimsEdges struct {
	// User holds the value of the user edge.
	User *User `json:"user,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
}

// UserOrErr returns the User value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e StandardClaimsEdges) UserOrErr() (*User, error) {
	if e.User != nil {
		return e.User, nil
	} else if e.loadedTypes[0] {
		return nil, &NotFoundError{label: user.Label}
	}
	return nil, &NotLoadedError{edge: "user"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*StandardClaims) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case standardclaims.FieldEmailVerified, standardclaims.FieldPhoneNumberVerified:
			values[i] = new(sql.NullBool)
		case standardclaims.FieldID, standardclaims.FieldUpdatedAt:
			values[i] = new(sql.NullInt64)
		case standardclaims.FieldSubject, standardclaims.FieldName, standardclaims.FieldGivenName, standardclaims.FieldFamilyName, standardclaims.FieldMiddleName, standardclaims.FieldNickname, standardclaims.FieldPreferredUsername, standardclaims.FieldProfile, standardclaims.FieldPicture, standardclaims.FieldWebsite, standardclaims.FieldEmail, standardclaims.FieldGender, standardclaims.FieldBirthdate, standardclaims.FieldZoneinfo, standardclaims.FieldLocale, standardclaims.FieldPhoneNumber, standardclaims.FieldAddress:
			values[i] = new(sql.NullString)
		case standardclaims.ForeignKeys[0]: // user_standard_claims
			values[i] = new(sql.NullString)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the StandardClaims fields.
func (sc *StandardClaims) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case standardclaims.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			sc.ID = int(value.Int64)
		case standardclaims.FieldSubject:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field subject", values[i])
			} else if value.Valid {
				sc.Subject = value.String
			}
		case standardclaims.FieldName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field name", values[i])
			} else if value.Valid {
				sc.Name = value.String
			}
		case standardclaims.FieldGivenName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field given_name", values[i])
			} else if value.Valid {
				sc.GivenName = value.String
			}
		case standardclaims.FieldFamilyName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field family_name", values[i])
			} else if value.Valid {
				sc.FamilyName = value.String
			}
		case standardclaims.FieldMiddleName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field middle_name", values[i])
			} else if value.Valid {
				sc.MiddleName = value.String
			}
		case standardclaims.FieldNickname:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field nickname", values[i])
			} else if value.Valid {
				sc.Nickname = value.String
			}
		case standardclaims.FieldPreferredUsername:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field preferred_username", values[i])
			} else if value.Valid {
				sc.PreferredUsername = value.String
			}
		case standardclaims.FieldProfile:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field profile", values[i])
			} else if value.Valid {
				sc.Profile = value.String
			}
		case standardclaims.FieldPicture:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field picture", values[i])
			} else if value.Valid {
				sc.Picture = value.String
			}
		case standardclaims.FieldWebsite:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field website", values[i])
			} else if value.Valid {
				sc.Website = value.String
			}
		case standardclaims.FieldEmail:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field email", values[i])
			} else if value.Valid {
				sc.Email = value.String
			}
		case standardclaims.FieldEmailVerified:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field email_verified", values[i])
			} else if value.Valid {
				sc.EmailVerified = value.Bool
			}
		case standardclaims.FieldGender:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field gender", values[i])
			} else if value.Valid {
				sc.Gender = value.String
			}
		case standardclaims.FieldBirthdate:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field birthdate", values[i])
			} else if value.Valid {
				sc.Birthdate = value.String
			}
		case standardclaims.FieldZoneinfo:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field zoneinfo", values[i])
			} else if value.Valid {
				sc.Zoneinfo = value.String
			}
		case standardclaims.FieldLocale:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field locale", values[i])
			} else if value.Valid {
				sc.Locale = value.String
			}
		case standardclaims.FieldPhoneNumber:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field phone_number", values[i])
			} else if value.Valid {
				sc.PhoneNumber = value.String
			}
		case standardclaims.FieldPhoneNumberVerified:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field phone_number_verified", values[i])
			} else if value.Valid {
				sc.PhoneNumberVerified = value.Bool
			}
		case standardclaims.FieldAddress:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field address", values[i])
			} else if value.Valid {
				sc.Address = value.String
			}
		case standardclaims.FieldUpdatedAt:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field updated_at", values[i])
			} else if value.Valid {
				sc.UpdatedAt = value.Int64
			}
		case standardclaims.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field user_standard_claims", values[i])
			} else if value.Valid {
				sc.user_standard_claims = new(string)
				*sc.user_standard_claims = value.String
			}
		default:
			sc.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the StandardClaims.
// This includes values selected through modifiers, order, etc.
func (sc *StandardClaims) Value(name string) (ent.Value, error) {
	return sc.selectValues.Get(name)
}

// QueryUser queries the "user" edge of the StandardClaims entity.
func (sc *StandardClaims) QueryUser() *UserQuery {
	return NewStandardClaimsClient(sc.config).QueryUser(sc)
}

// Update returns a builder for updating this StandardClaims.
// Note that you need to call StandardClaims.Unwrap() before calling this method if this StandardClaims
// was returned from a transaction, and the transaction was committed or rolled back.
func (sc *StandardClaims) Update() *StandardClaimsUpdateOne {
	return NewStandardClaimsClient(sc.config).UpdateOne(sc)
}

// Unwrap unwraps the StandardClaims entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (sc *StandardClaims) Unwrap() *StandardClaims {
	_tx, ok := sc.config.driver.(*txDriver)
	if !ok {
		panic("ent: StandardClaims is not a transactional entity")
	}
	sc.config.driver = _tx.drv
	return sc
}

// String implements the fmt.Stringer.
func (sc *StandardClaims) String() string {
	var builder strings.Builder
	builder.WriteString("StandardClaims(")
	builder.WriteString(fmt.Sprintf("id=%v, ", sc.ID))
	builder.WriteString("subject=")
	builder.WriteString(sc.Subject)
	builder.WriteString(", ")
	builder.WriteString("name=")
	builder.WriteString(sc.Name)
	builder.WriteString(", ")
	builder.WriteString("given_name=")
	builder.WriteString(sc.GivenName)
	builder.WriteString(", ")
	builder.WriteString("family_name=")
	builder.WriteString(sc.FamilyName)
	builder.WriteString(", ")
	builder.WriteString("middle_name=")
	builder.WriteString(sc.MiddleName)
	builder.WriteString(", ")
	builder.WriteString("nickname=")
	builder.WriteString(sc.Nickname)
	builder.WriteString(", ")
	builder.WriteString("preferred_username=")
	builder.WriteString(sc.PreferredUsername)
	builder.WriteString(", ")
	builder.WriteString("profile=")
	builder.WriteString(sc.Profile)
	builder.WriteString(", ")
	builder.WriteString("picture=")
	builder.WriteString(sc.Picture)
	builder.WriteString(", ")
	builder.WriteString("website=")
	builder.WriteString(sc.Website)
	builder.WriteString(", ")
	builder.WriteString("email=")
	builder.WriteString(sc.Email)
	builder.WriteString(", ")
	builder.WriteString("email_verified=")
	builder.WriteString(fmt.Sprintf("%v", sc.EmailVerified))
	builder.WriteString(", ")
	builder.WriteString("gender=")
	builder.WriteString(sc.Gender)
	builder.WriteString(", ")
	builder.WriteString("birthdate=")
	builder.WriteString(sc.Birthdate)
	builder.WriteString(", ")
	builder.WriteString("zoneinfo=")
	builder.WriteString(sc.Zoneinfo)
	builder.WriteString(", ")
	builder.WriteString("locale=")
	builder.WriteString(sc.Locale)
	builder.WriteString(", ")
	builder.WriteString("phone_number=")
	builder.WriteString(sc.PhoneNumber)
	builder.WriteString(", ")
	builder.WriteString("phone_number_verified=")
	builder.WriteString(fmt.Sprintf("%v", sc.PhoneNumberVerified))
	builder.WriteString(", ")
	builder.WriteString("address=")
	builder.WriteString(sc.Address)
	builder.WriteString(", ")
	builder.WriteString("updated_at=")
	builder.WriteString(fmt.Sprintf("%v", sc.UpdatedAt))
	builder.WriteByte(')')
	return builder.String()
}

// StandardClaimsSlice is a parsable slice of StandardClaims.
type StandardClaimsSlice []*StandardClaims