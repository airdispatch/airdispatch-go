package common

import (
	"errors"
)

type ADMessage struct {
	payload     map[string]*ADComponent
	messageType string
	fromAddress *ADAddress
	toAddress   *ADAddress
}

func (a *ADMessage) HasDataType(typeName string) bool {
	_, ok := a.payload[typeName]
	return ok
}

func (a *ADMessage) GetADComponentForType(typeName string) (*ADComponent, error) {
	v, ok := a.payload[typeName]
	if !ok {
		return nil, errors.New("ADMessage doesn't contain that Type")
	}

	return v, nil
}

func (a *ADMessagePrimative) CastToADMessage() *ADMessage {
	return nil
}

func (a *ADMessage) CastToADMessagePrimative() *ADMessagePrimative {
	return nil
}

func (a *ADMessage) ToBytes() []byte {
	return a.CastToADMessagePrimative().ToBytes()
}

func (a *ADMessagePrimative) ToBytes() []byte {
	return nil
}

func CreateADMessage(fromAddress string, toAddress string, messageType string, payload []*ADComponent) *ADMessage {
	output := &ADMessage{}

	output.fromAddress = fromAddress
	output.toAddress = toAddress
	output.messageType = messageType

	componentMap := new(map[string]*ADComponent)
	for i, v := range payload {
		componentMap[v.data_type] = v
	}

	output.payload = componentMap

	return output
}

type ADComponent struct {
	data_type      string
	data_component []byte
}

func (a *ADComponent) StringValue() string {
	return string(a.data_component)
}

func (a *ADComponent) ByteValue() []byte {
	return a.data_component
}

func (a *ADComponent) DataTypeValue() string {
	return a.data_type
}

func CreateADComponent(name string, data []byte) *ADComponent {
	return &ADComponent{name, data}
}

type ADAddress struct {
	associatedKey *ADKey
}
