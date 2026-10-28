package management

import (
	"bytes"
	"encoding/json"
	"errors"
)

func relayJSON(body []byte, target any) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return err
	}
	if fields == nil {
		return errors.New("relay input must be an object")
	}
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("relay fields cannot be null")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}
func (value *RelayNodeInput) UnmarshalJSON(body []byte) error {
	type alias RelayNodeInput
	return relayJSON(body, (*alias)(value))
}
func (value *RelayNodeUpdate) UnmarshalJSON(body []byte) error {
	type alias RelayNodeUpdate
	return relayJSON(body, (*alias)(value))
}
