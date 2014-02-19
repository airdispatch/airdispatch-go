package server

import (
	"airdispat.ch/message"
	"airdispat.ch/wire"
	"code.google.com/p/goprotobuf/proto"
)

type MessageDescription struct {
	Name     string
	Location string
	Nonce    uint64
	h        message.Header
}

func CreateMessageDescriptionFromBytes(by []byte, h message.Header) (*MessageDescription, error) {
	var fromData *wire.MessageDescription
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

type TransferMessage struct {
	Name string
	h    message.Header
}

func CreateTransferMessageFromBytes(by []byte, h message.Header) (*TransferMessage, error) {
	var fromData *wire.TransferMessage
	err := proto.Unmarshal(by, fromData)
	if err != nil {
		return nil, err
	}

	return &TransferMessage{
		Name: fromData.GetName(),
		h:    h,
	}, nil
}

func (m *TransferMessage) ToBytes() []byte {
	toData := &wire.TransferMessage{
		Name: &m.Name,
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
	Content []*MessageDescription
	h       message.Header
}

func (m *MessageList) AddMessageDescription(md *MessageDescription) {
	m.Content = append(m.Content, md)
}

func (m *MessageList) ToBytes() []byte {
	wired := make([]*wire.MessageDescription, len(m.Content))
	for i, v := range m.Content {
		wired[i] = v.toWire()
	}

	toData := &wire.MessageList{
		Messages: wired,
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
	Since uint64
	h     message.Header
}

func CreateTransferMessageListFromBytes(by []byte, h message.Header) (*TransferMessageList, error) {
	var fromData *wire.TransferMessageList
	err := proto.Unmarshal(by, fromData)
	if err != nil {
		return nil, err
	}

	return &TransferMessageList{
		Since: fromData.GetLastUpdated(),
		h:     h,
	}, nil
}

func (m *TransferMessageList) ToBytes() []byte {
	toData := &wire.TransferMessageList{
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
