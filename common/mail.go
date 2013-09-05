package common

import (
	"airdispat.ch/airdispatch"
	"code.google.com/p/goprotobuf/proto"
	"errors"
)

type ADMail struct {
	payload map[string]*ADComponent

	encryptedPayload []byte
	encryptionType   string

	FromAddress *ADAddress
	ToAddress   *ADAddress
	Timestamp   uint64
}

func (a *ADMail) HasDataType(typeName string) bool {
	_, ok := a.payload[typeName]
	return ok
}

func (a *ADMail) GetADComponentForType(typeName string) (*ADComponent, error) {
	v, ok := a.payload[typeName]
	if !ok {
		return nil, errors.New("ADMail doesn't contain that Type")
	}

	return v, nil
}

func (a *ADMail) ToBytes() []byte {
	return nil
}

func (a *ADMail) marshalComponents() []byte {

	return nil
}

func CreateADMailFromADMessage(message *ADMessage) (*ADMail, error) {
	if message.MessageType != MAIL_MESSAGE {
		return nil, errors.New("Cannot translate an ADMessage with incorrect message type to ADMail.")
	}

	output := &ADMail{}

	theMessage := &airdispatch.Mail{}
	err := proto.Unmarshal(message.Payload, theMessage)
	if err != nil {
		return nil, ADUnmarshallingError
	}

	output.FromAddress = message.FromAddress

	// TODO: Verify Addresses Match

	output.ToAddress = CreateADAddress(theMessage.GetToAddress())
	if output.ToAddress == nil {
		return nil, errors.New("Couldn't resolve To Address")
	}

	output.Timestamp = theMessage.GetTimestamp()
	output.encryptedPayload = theMessage.GetData()

	return output, nil
}

func CreateADMail(fromAddress *ADAddress, toAddress *ADAddress, timestamp uint64, payload []*ADComponent) *ADMail {
	output := &ADMail{}

	output.FromAddress = fromAddress
	output.ToAddress = toAddress
	output.Timestamp = timestamp

	componentMap := make(map[string]*ADComponent)
	for _, v := range payload {
		componentMap[v.DataTypeValue()] = v
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

func CreateADComponentFromBytes(theBytes []byte) *ADComponent {
	return CreateADComponent("Test", []byte("Test"))
}

func (a *ADComponent) ToPrimative() *airdispatch.MailData_DataType {
	newDataType := &airdispatch.MailData_DataType{}

	newDataType.Payload = a.data_component
	newDataType.TypeName = &a.data_type

	return newDataType
}
