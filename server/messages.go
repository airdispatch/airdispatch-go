package server

import (
	"time"

	"airdispat.ch/crypto"
	"airdispat.ch/identity"
	"airdispat.ch/message"
	"airdispat.ch/wire"
	"code.google.com/p/goprotobuf/proto"
)

func createHeader(from *identity.Address, to ...*identity.Address) message.Header {
	header := message.CreateHeader(from, to...)
	header.EncryptionKey = crypto.RSAToBytes(from.EncryptionKey)
	return header
}

func CreateMessageDescription(name string, location string, from *identity.Address, to *identity.Address) *MessageDescription {
	return &MessageDescription{
		Name:     name,
		Location: location,
		h:        message.CreateHeader(from, to),
	}
}

func CreateMessageList(from *identity.Address, to *identity.Address) *MessageList {
	return &MessageList{
		h: message.CreateHeader(from, to),
	}
}

func CreateTransferMessage(name string, from *identity.Address, to *identity.Address, author *identity.Address) *TransferMessage {
	return &TransferMessage{
		Name:   name,
		Author: author,
		h:      createHeader(from, to),
	}
}

func CreateTransferMessageList(since uint64, from *identity.Address, to *identity.Address, author *identity.Address) *TransferMessageList {
	return &TransferMessageList{
		Author: author,
		Since:  since,
		h:      createHeader(from, to),
	}
}

type MessageDescription struct {
	Name     string
	Location string
	Nonce    uint64
	h        message.Header
}

func CreateMessageDescriptionFromBytes(by []byte, h message.Header) (*MessageDescription, error) {
	fromData := &wire.MessageDescription{}
	err := proto.Unmarshal(by, fromData)
	if err != nil {
		return nil, err
	}

	return &MessageDescription{
		Name:     fromData.GetName(),
		Location: fromData.GetLocation(),
		Nonce:    fromData.GetNonce(),
		h:        h,
	}, nil
}

func (m *MessageDescription) toWire() *wire.MessageDescription {
	return &wire.MessageDescription{
		Name:     &m.Name,
		Location: &m.Location,
		Nonce:    &m.Nonce,
	}
}

func (m *MessageDescription) ToBytes() []byte {
	by, err := proto.Marshal(m.toWire())
	if err != nil {
		panic("Can't marshal MessageDescription.")
	}
	return by
}

func (m *MessageDescription) Type() string {
	return wire.MessageDescriptionCode
}

func (m *MessageDescription) Header() message.Header {
	return m.h
}

func (m *MessageDescription) GenerateTransferRequest() *TransferMessage {
	hdr := createHeader(m.h.From, m.h.To...)
	hdr.Timestamp = time.Now().Unix()

	return &TransferMessage{
		Name: m.Name,
		h:    hdr,
	}
}

type TransferMessage struct {
	Name   string
	Author *identity.Address
	h      message.Header
}

func CreateTransferMessageFromBytes(by []byte, h message.Header) (*TransferMessage, error) {
	fromData := &wire.TransferMessage{}
	err := proto.Unmarshal(by, fromData)
	if err != nil {
		return nil, err
	}

	return &TransferMessage{
		Author: identity.CreateAddressFromString(fromData.GetAuthor()),
		Name:   fromData.GetName(),
		h:      h,
	}, nil
}

func (m *TransferMessage) ToBytes() []byte {
	author := m.Author.String()
	toData := &wire.TransferMessage{
		Name:   &m.Name,
		Author: &author,
	}
	by, err := proto.Marshal(toData)
	if err != nil {
		panic("Can't marshal TransferMessage.")
	}
	return by
}

func (m *TransferMessage) Type() string {
	return wire.TransferMessageCode
}

func (m *TransferMessage) Header() message.Header {
	return m.h
}

// --- Multi-Messages ---
type MessageList struct {
	Length uint64
	h      message.Header
}

func CreateMessageListFromBytes(b []byte, h message.Header) (*MessageList, error) {
	unmarsh := &wire.MessageList{}
	err := proto.Unmarshal(b, unmarsh)
	if err != nil {
		return nil, err
	}

	out := &MessageList{
		Length: unmarsh.GetLength(),
		h:      h,
	}
	return out, nil
}

func (m *MessageList) ToBytes() []byte {
	toData := &wire.MessageList{
		Length: &m.Length,
	}
	by, err := proto.Marshal(toData)
	if err != nil {
		panic("Can't marshal MessageList.")
	}
	return by
}

func (m *MessageList) Type() string {
	return wire.MessageListCode
}

func (m *MessageList) Header() message.Header {
	return m.h
}

type TransferMessageList struct {
	Author *identity.Address
	Since  uint64
	h      message.Header
}

func CreateTransferMessageListFromBytes(by []byte, h message.Header) (*TransferMessageList, error) {
	fromData := &wire.TransferMessageList{}
	err := proto.Unmarshal(by, fromData)
	if err != nil {
		return nil, err
	}

	return &TransferMessageList{
		Author: identity.CreateAddressFromString(fromData.GetAuthor()),
		Since:  fromData.GetLastUpdated(),
		h:      h,
	}, nil
}

func (m *TransferMessageList) ToBytes() []byte {
	author := m.Author.String()
	toData := &wire.TransferMessageList{
		Author:      &author,
		LastUpdated: &m.Since,
	}
	by, err := proto.Marshal(toData)
	if err != nil {
		panic("Can't marshal TransferMessageList.")
	}
	return by
}

func (m *TransferMessageList) Type() string {
	return wire.TransferMessageListCode
}

func (m *TransferMessageList) Header() message.Header {
	return m.h
}
