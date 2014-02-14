package message

import (
	"airdispat.ch/identity"
)

type Message interface {
	Header() Header
	Type() string
	ToBytes() []byte
}

type Header struct {
	From      *identity.Address
	To        *identity.Address
	Timestamp int64
}

type SignedMessage struct {
	Message   Message
	Signature Signature
}

// Encrypt(router)
// EncryptWithKey(key)
// Verify() bool

type EncryptedMessage struct {
	SignedMessage  Message
	EncryptionKey  []byte
	EncryptionType string
	To             *identity.Address
}

// SendToServer(loc)
// Send(router)
// Decrypt(id) SignedMessage
