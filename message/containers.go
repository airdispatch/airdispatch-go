package message

import (
	"net"
	"time"

	"airdispat.ch/crypto"
	"airdispat.ch/identity"
	"airdispat.ch/wire"
)

// Message is an interface that allows something to be sent on the AirDispatch
// wire. It requires a message that knows how to marshal itself to bytes
// (ToBytes()), retrieve a header (Header()), and return a message type (Type()).
type Message interface {
	Header() Header
	Type() string
	ToBytes() []byte
}

// SignAndSend will take a message, a from identity, and a to address, and send
// it to the address (so long as to already contains key information).
func SignAndSend(m Message, from *identity.Identity, to *identity.Address) error {
	signed, err := SignMessage(m, from)
	if err != nil {
		return err
	}

	encrypted, err := signed.EncryptWithKey(to)
	if err != nil {
		return err
	}

	return encrypted.Send()
}

// SignAndSendToConnection performs exactly the same function as SignAndSend, but
// it can utilize an already open connection. Useful for responding to messages.
func SignAndSendToConnection(m Message, from *identity.Identity, to *identity.Address, conn net.Conn) error {
	signed, err := SignMessage(m, from)
	if err != nil {
		return err
	}

	encrypted, err := signed.EncryptWithKey(to)
	if err != nil {
		return err
	}

	return encrypted.SendMessageToConnection(conn)
}

// Header is a message header that is sent across the wire signed and encrypted.
//
// Each public field is an object that is important to be protected.
type Header struct {
	From      *identity.Address
	To        *identity.Address
	Timestamp int64
	// Location Options
	EncryptionKey []byte
	Alias         string
}

// CreateHeader will return a basic header for a from address and a to address.
func CreateHeader(from *identity.Address, to *identity.Address) Header {
	return Header{
		From:      from,
		To:        to,
		Timestamp: time.Now().Unix(),
	}
}

// createHeaderFromWire will unmarshal a header
func createHeaderFromWire(w *wire.Header) (Header, error) {
	from := identity.CreateAddressFromBytes(w.GetFromAddr())

	if len(w.GetEncryptionKey()) != 0 {
		var err error
		from.EncryptionKey, err = crypto.BytesToRSA(w.GetEncryptionKey())
		if err != nil {
			return Header{}, err
		}
	}

	if w.GetAlias() != "" {
		from.Alias = w.GetAlias()
	}

	return Header{
		From:          from,
		To:            identity.CreateAddressFromBytes(w.GetToAddr()),
		Timestamp:     int64(w.GetTimestamp()),
		EncryptionKey: w.GetEncryptionKey(),
		Alias:         w.GetAlias(),
	}, nil
}

// toWire will marshal a header
func (h Header) toWire() *wire.Header {
	time := uint64(h.Timestamp)

	// Public Messages are Allowed
	toAddr := []byte{0}
	if h.To != nil && !h.To.IsPublic() {
		toAddr = h.To.Fingerprint
	}

	return &wire.Header{
		FromAddr:      h.From.Fingerprint,
		ToAddr:        toAddr,
		Timestamp:     &time,
		EncryptionKey: h.EncryptionKey,
		Alias:         &h.Alias,
	}
}
