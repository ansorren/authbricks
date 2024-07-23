package api

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/pkg/errors"
)

// Unmarshaler is a generic type to unmarshal a io.Reader.
type Unmarshaler[T any] struct {
	reader io.Reader
}

// NewUnmarshaler instantiates a new Unmarshaler.
func NewUnmarshaler[T any](reader io.Reader) *Unmarshaler[T] {
	return &Unmarshaler[T]{
		reader: reader,
	}
}

// Unmarshal takes care of unmarshaling the data into the given type T.
func (u *Unmarshaler[T]) Unmarshal() (T, error) {
	op := "Unmarshal"
	var ret T
	var buf bytes.Buffer
	_, err := buf.ReadFrom(u.reader)
	if err != nil {
		return ret, errors.Wrapf(err, "%s: unable to read from reader", op)
	}
	err = json.Unmarshal(buf.Bytes(), &ret)
	if err != nil {
		return ret, errors.Wrapf(err, "%s: unable to unmarshal json", op)
	}

	return ret, nil
}
