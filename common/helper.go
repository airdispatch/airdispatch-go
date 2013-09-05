package common

import (
	"airdispat.ch/airdispatch"
	"code.google.com/p/goprotobuf/proto"
	"reflect"
)

func (a *ADKey) SignBytes(payload []byte) (*airdispatch.Signature, error) {
	r, s, err := signPayload(a.SignatureKey, payload)
	if err != nil {
		return nil, err
	}

	newSignature := &airdispatch.Signature{
		R: r.Bytes(),
		S: s.Bytes(),
	}
	return newSignature, nil
}

func (a *ADKey) CreateArrayedMessage(itemLength uint32) (*ADMessage, error) {
	newArray := &airdispatch.ArrayedData{
		NumberOfMessages: &itemLength,
	}
	dataArray, err := proto.Marshal(newArray)
	if err != nil {
		return nil, err
	}

	newMessage := &ADMessage{
		Payload:     dataArray,
		MessageType: ARRAY_MESSAGE,
	}

	return newMessage, nil
}

func (a *ADKey) CreateErrorMessage(code string, description string) *ADMessage {
	newError := &airdispatch.Error{
		Code:        &code,
		Description: &description,
	}

	data, err := proto.Marshal(newError)
	if err != nil {
		// We're screwed.
		return nil
	}

	newMessage := &ADMessage{
		Payload:     data,
		MessageType: ERROR_MESSAGE,
	}

	return newMessage
}

func SliceContains(array interface{}, elem interface{}) bool {
	v := reflect.ValueOf(array)
	for i := 0; i < v.Len(); i++ {
		if v.Index(i).Interface() == elem {
			return true
		}
	}
	return false
}
