package message

import (
	"bytes"
	"errors"

	"airdispat.ch/crypto"
	"airdispat.ch/identity"
	"airdispat.ch/wire"
	"code.google.com/p/goprotobuf/proto"
)

// EncryptedMessage represents an AirDispatch message encrypted for
// one or many recipients.
type EncryptedMessage struct {
	Data           []byte
	Header         map[string]EncryptionHeader
	unencryptedKey crypto.AESKey
}

// EncryptionHeader holds the information necessary for a recipient to decrypt
// the message.
type EncryptionHeader struct {
	EncryptionKey  []byte
	EncryptionType []byte
	To             *identity.Address
}

// CreateEncryptedMessageFromBytes will take a series of bytes (usually read
// read from a connection) and Unmarshal them into the EncryptedMessage struct.
func CreateEncryptedMessageFromBytes(theBytes []byte) (*EncryptedMessage, error) {
	downloadedMessage := &wire.EncryptedMessage{}
	err := proto.Unmarshal(theBytes, downloadedMessage)
	if err != nil {
		return nil, err
	}

	output := &EncryptedMessage{}

	output.Header = make(map[string]EncryptionHeader)
	for _, v := range downloadedMessage.GetHeader() {
		toAddr := identity.CreateAddressFromBytes(v.GetToAddr())
		header := EncryptionHeader{
			EncryptionKey:  v.GetKey(),
			EncryptionType: v.GetEncFun(),
			To:             toAddr,
		}
		output.Header[toAddr.String()] = header
	}

	output.Data = downloadedMessage.GetData()
	return output, nil
}

// AddRecipient will take an *identity.Address and add information for it
// to decrypt the message.
func (e *EncryptedMessage) AddRecipient(addr *identity.Address) error {
	if e.unencryptedKey == nil {
		return errors.New("Can't add recipient to a message that won't be encrypted.")
	}

	if e.Header == nil {
		e.Header = make(map[string]EncryptionHeader)
	}

	key, err := crypto.EncryptAESKey(e.unencryptedKey, addr.EncryptionKey)
	if err != nil {
		return err
	}

	e.Header[addr.String()] = EncryptionHeader{
		EncryptionKey:  key,
		EncryptionType: crypto.EncryptionRSA,
		To:             addr,
	}
	return nil
}

// Send will connect to each recipient's server and send the message to them.
func (e *EncryptedMessage) Send() error {
	if e.Header == nil || len(e.Header) == 0 {
		return errors.New("Can't send message without a receipient.")
	}

	for _, v := range e.Header {
		if v.To.Location == "" {
			return errors.New("Cannot send to address without location.")
		}

		conn, err := ConnectToServer(v.To.Location)
		if err != nil {
			return err
		}
		defer conn.Close()

		err = e.SendMessageToConnection(conn)
		if err != nil {
			return err
		}
	}

	return nil
}

// Decrypt will use an *identity.Identity to decrypt the EncryptedMessage
// into a SignedMessage.
func (e *EncryptedMessage) Decrypt(id *identity.Identity) (*SignedMessage, error) {
	if e.Header == nil || len(e.Header) == 0 {
		return e.UnencryptedMessage()
	}

	data, ok := e.Header[id.Address.String()]
	if !ok {
		return nil, errors.New("Can't decrypt message that isn't for you.")
	}

	if bytes.Equal(data.EncryptionType, crypto.EncryptionNone) {
		return e.UnencryptedMessage()
	}

	// Decrypt the data from the cipher.
	p, err := crypto.HybridDecryption(id.EncryptionKey, data.EncryptionKey, e.Data)
	if err != nil {
		return nil, err
	}

	// Unmarshal the wire data
	x := &wire.SignedMessage{}
	err = proto.Unmarshal(p, x)
	if err != nil {
		return nil, err
	}

	// Create a signedmessage
	sm := &SignedMessage{
		Data:        x.GetData(),
		Signature:   x.GetSignature(),
		SigningFunc: x.GetSigningFunc(),
	}

	// Return the signed message
	return sm, nil
}

// UnencryptedMessage will downgrade an EncryptedMessage into a SignedMessage
// if you know that the message is not encrypted.
func (e *EncryptedMessage) UnencryptedMessage() (*SignedMessage, error) {
	// Unmarshal the wire data
	x := &wire.SignedMessage{}
	err := proto.Unmarshal(e.Data, x)
	if err != nil {
		return nil, err
	}

	// Create a signedmessage
	sm := &SignedMessage{
		Data:        x.GetData(),
		Signature:   x.GetSignature(),
		SigningFunc: x.GetSigningFunc(),
	}

	// Return the signed message
	return sm, nil
}

// Reconstruct will take an change an encrypted message into a message blob
// Message Type, Header, and Error by Decrypting with the receiver's identity,
// verifying the signed message, and reconstructing the signed message
// (optionally with timestamp support).
func (e *EncryptedMessage) Reconstruct(receiver *identity.Identity, ts bool) ([]byte, string, Header, error) {
	receivedSign, err := e.Decrypt(receiver)
	if err != nil {
		return nil, "", Header{}, err
	}

	if !receivedSign.Verify() {
		return nil, "", Header{}, errors.New("Unable to Verify Message")
	}

	if ts {
		return receivedSign.ReconstructMessageWithTimestamp()
	}
	return receivedSign.ReconstructMessage()
}

// ToBytes will marshal an EncryptedMessage to an array of bytes
// suitable for sending on a wire.
func (e *EncryptedMessage) ToBytes() ([]byte, error) {
	// The first step to sending the message is marshalling it to bytes.
	toData := &wire.EncryptedMessage{
		Data: e.Data,
	}

	hdrs := make([]*wire.EncryptedHeader, len(e.Header))

	i := 0
	for _, v := range e.Header {

		toAddr := []byte{0}
		if v.To != nil && !v.To.IsPublic() {
			toAddr = v.To.Fingerprint
		}

		hdrs[i] = &wire.EncryptedHeader{
			ToAddr: toAddr,
			EncFun: v.EncryptionType,
			Key:    v.EncryptionKey,
		}
		i++
	}

	return proto.Marshal(toData)
}
