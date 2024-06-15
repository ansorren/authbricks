// Code generated by ent, DO NOT EDIT.

package cookiestore

import (
	"entgo.io/ent/dialect/sql"
)

const (
	// Label holds the string label denoting the cookiestore type in the database.
	Label = "cookie_store"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldAuthKey holds the string denoting the auth_key field in the database.
	FieldAuthKey = "auth_key"
	// FieldEncryptionKey holds the string denoting the encryption_key field in the database.
	FieldEncryptionKey = "encryption_key"
	// Table holds the table name of the cookiestore in the database.
	Table = "cookie_stores"
)

// Columns holds all SQL columns for cookiestore fields.
var Columns = []string{
	FieldID,
	FieldAuthKey,
	FieldEncryptionKey,
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	return false
}

var (
	// AuthKeyValidator is a validator for the "auth_key" field. It is called by the builders before save.
	AuthKeyValidator func(string) error
	// EncryptionKeyValidator is a validator for the "encryption_key" field. It is called by the builders before save.
	EncryptionKeyValidator func(string) error
	// IDValidator is a validator for the "id" field. It is called by the builders before save.
	IDValidator func(string) error
)

// OrderOption defines the ordering options for the CookieStore queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByAuthKey orders the results by the auth_key field.
func ByAuthKey(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldAuthKey, opts...).ToFunc()
}

// ByEncryptionKey orders the results by the encryption_key field.
func ByEncryptionKey(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldEncryptionKey, opts...).ToFunc()
}
