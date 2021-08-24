package encryptedbox

import (
	"encoding/json"
	"errors"
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
	return json.Marshal(s)
}

func (jsonSerializer) Deserialize(d []byte, v interface{}) error {
	return json.Unmarshal(d, v)
}
