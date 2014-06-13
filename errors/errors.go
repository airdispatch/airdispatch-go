package errors

import (
	"airdispat.ch/identity"
	"airdispat.ch/message"
	"airdispat.ch/wire"
	"code.google.com/p/goprotobuf/proto"
	"fmt"
	"net"
)

type Error struct {
	Code        uint32
	Description string
	h           message.Header
}

func (e *Error) Error() string {
	return fmt.Sprintf("%d: %s", e.Code, e.Description)
}

func (e *Error) Prepare(from *identity.Address) {
	e.h = message.CreateHeader(from, identity.Public)
}

func (e *Error) Type() string {
	return wire.ErrorCode
}

func (e *Error) ToBytes() []byte {
	wireFormat := &wire.Error{
		Code:        &e.Code,
		Description: &e.Description,
	}
	by, err := proto.Marshal(wireFormat)
	if err != nil {
		panic("Unable to marshal error message. What now?")
	}
	return by
}

func (e *Error) Header() message.Header {
	if e.h.From == nil {
		panic("Can't return empty header.")
	}
	return e.h
}

func CreateErrorFromBytes(by []byte, h message.Header) *Error {
	unmarsh := &wire.Error{}
	err := proto.Unmarshal(by, unmarsh)
	if err != nil {
		return &Error{10, "Unable to unmarshal Error message.", h}
	}

	return &Error{
		Code:        unmarsh.GetCode(),
		Description: unmarsh.GetDescription(),
		h:           h,
	}
}

func CreateError(code Code, description string, from *identity.Address) *Error {
	e := &Error{
		Code:        uint32(code),
		Description: description,
	}

	return e
}

func (e *Error) Send(from *identity.Identity, conn net.Conn) error {
	return message.SignAndSendToConnection(e, from, identity.Public, conn)
}
