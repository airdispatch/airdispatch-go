package common

import (
	"errors"
	"fmt"
)

func (a *ADMessage) HasDataType(typeName string) bool {
	_, ok := a.Payload[typeName]
	return ok
}

func (a *ADMessage) GetDataTypeValue(typeName string) ([]byte, error) {
	v, ok := a.Payload[typeName]
	if !ok {
		return nil, errors.New("ADMessage doesn't contain that Type")
	}

	return v, nil
}

func (a *ADMessage) GetStringDataTypeValue(typeName string) (string, error) {
	v, err := a.GetType(typeName)

	if err != nil {
		return "", err
	}

	return string(v), nil
}

func (a *ADMessagePrimative)