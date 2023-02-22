package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
)

// RawMessage custom raw message []byte
type RawMessage []byte

// MarshalJSON returns m as the JSON encoding of m.
func (m RawMessage) MarshalJSON() ([]byte, error) {
	if m == nil {
		return []byte("null"), nil
	}
	return m, nil
}

// UnmarshalJSON sets *m to a copy of data.
func (m *RawMessage) UnmarshalJSON(data []byte) error {
	if m == nil {
		return errors.New("RawMessage: UnmarshalJSON on nil pointer")
	}
	*m = append((*m)[0:0], data...)
	return nil
}

// Scan scan value into Jsonb, implements sql.Scanner interface
func (m *RawMessage) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New(fmt.Sprint("Failed to unmarshal JSONB value:", value))
	}

	result := RawMessage{}
	err := json.Unmarshal(bytes, &result)
	*m = RawMessage(result)
	return err
}

// Value return json value, implement driver.Valuer interface
func (m RawMessage) Value() (driver.Value, error) {
	if len(m) == 0 {
		return nil, nil
	}
	return RawMessage(m).MarshalJSON()
}
