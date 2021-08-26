package encryptedbox

import (
	"encoding/json"
	"errors"
	"fmt"
)

var (
	String Serializer = stringSerializer{}
	Bytes  Serializer = bytesSerializer{}
	JSON   Serializer = jsonSerializer{}
)

type stringSerializer struct{}

func (stringSerializer) Serialize(data interface{}) ([]byte, error) {
	str, ok := data.(string)
	if !ok {
		return nil, errors.New("expected interface to contain a string")
	}
	return []byte(str), nil
}

func (stringSerializer) Deserialize(data []byte, dst interface{}) error {
	d, ok := dst.(*string)
	if !ok {
		return errors.New("expected interface to contain a *string")
	}
	*d = string(data)
	return nil
}

type bytesSerializer struct{}

func (bytesSerializer) Serialize(data interface{}) ([]byte, error) {
	b, ok := data.([]byte)
	if !ok {
		return nil, errors.New("expected interface to contain a []byte")
	}
	return b, nil
}

func (bytesSerializer) Deserialize(data []byte, dst interface{}) error {
	d, ok := dst.(*[]byte)
	if !ok {
		return errors.New("expected interface to contain a *[]byte")
	}
	*d = data
	return nil
}

type jsonSerializer struct{}

func (jsonSerializer) Serialize(s interface{}) ([]byte, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("json serialization failed: %w", err)
	}
	return b, nil
}

func (jsonSerializer) Deserialize(d []byte, v interface{}) error {
	err := json.Unmarshal(d, v)
	if err != nil {
		return fmt.Errorf("json deserialization failed: %w", err)
	}
	return nil
}
