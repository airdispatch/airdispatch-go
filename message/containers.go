package message

import (
	"airdispat.ch/crypto"
	"airdispat.ch/identity"
	"airdispat.ch/routing"
	"airdispat.ch/wire"
	"bytes"
	"code.google.com/p/goprotobuf/proto"
	"errors"
	"math/big"
	"net"
	"time"
)

type Message interface {
	Header() Header
	Type() string
	ToBytes() []byte
}

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

func SignMessage(m Message, id *identity.Identity) (*SignedMessage, error) {
	messageType := m.Type()

	toData := &wire.Container{
		Header: m.Header().ToWire(),
		Data:   m.ToBytes(),
		Type:   &messageType,
	}

	if toData.Data == nil {
		return nil, errors.New("Unable to marshal message to bytes.")
	}

	toSign, err := proto.Marshal(toData)
	if err != nil {
		return nil, err
	}

	r, s, err := crypto.SignPayload(id.SigningKey, crypto.HashSHA(toSign))
	if err != nil {
		return nil, err
	}

	newSignature := &wire.Signature{
		R:          r.Bytes(),
		S:          s.Bytes(),
		SigningKey: crypto.KeyToBytes(&id.SigningKey.PublicKey),
	}

	newSignedMessage := &SignedMessage{
		Data:        toSign,
		Signature:   []*wire.Signature{newSignature},
		SigningFunc: crypto.SigningECDSA,
	}
	return newSignedMessage, nil
}

// Common AirDispatch Header
type Header struct {
	From      *identity.Address
	To        *identity.Address
	Timestamp int64
}

func CreateHeader(from *identity.Address, to *identity.Address) Header {
	return Header{
		From:      from,
		To:        to,
		Timestamp: time.Now().Unix(),
	}
}

func CreateHeaderFromWire(w *wire.Header) Header {
	return Header{
		From:      identity.CreateAddressFromBytes(w.GetFromAddr()),
		To:        identity.CreateAddressFromBytes(w.GetToAddr()),
		Timestamp: int64(w.GetTimestamp()),
	}
}

func (h Header) ToWire() *wire.Header {
	time := uint64(h.Timestamp)

	// Public Messages are Allowed
	toAddr := []byte{0}
	if h.To != nil {
		toAddr = h.To.Fingerprint
	}

	return &wire.Header{
		FromAddr:  h.From.Fingerprint,
		ToAddr:    toAddr,
		Timestamp: &time,
	}
}

// Container Message for Signed Data
type SignedMessage struct {
	Data        []byte
	Signature   []*wire.Signature
	SigningFunc []byte
}

func (s *SignedMessage) AddSignature(id *identity.Identity) error {
	rInt, sInt, err := crypto.SignPayload(id.SigningKey, crypto.HashSHA(s.Data))
	if err != nil {
		return err
	}

	newSignature := &wire.Signature{
		R:          rInt.Bytes(),
		S:          sInt.Bytes(),
		SigningKey: crypto.KeyToBytes(&id.SigningKey.PublicKey),
	}

	s.Signature = append(s.Signature, newSignature)
	return nil
}

func (s *SignedMessage) ReconstructMessage() (data []byte, messageType string, header Header, err error) {
	unmarshaller := &wire.Container{}
	err = proto.Unmarshal(s.Data, unmarshaller)
	if err != nil {
		return
	}

	messageType = unmarshaller.GetType()
	data = unmarshaller.GetData()
	header = CreateHeaderFromWire(unmarshaller.GetHeader())
	header.From = identity.CreateAddressFromBytes(s.Signature[0].SigningKey)

	if header.Timestamp < time.Now().Unix()-600 ||
		header.Timestamp > time.Now().Unix() {
		err = errors.New("Unable to verify message timestamp.")
	}

	return
}

// Encrypt a signed message for an Address Fingerprint (String)
func (s *SignedMessage) Encrypt(addr string, router routing.Router) (*EncryptedMessage, error) {
	fullAddress, err := router.Lookup(addr)
	if err != nil {
		return nil, err
	}

	return s.EncryptWithKey(fullAddress)
}

// Encrypt a signed message for a qualified Address
func (s *SignedMessage) EncryptWithKey(addr *identity.Address) (*EncryptedMessage, error) {
	// Create a SignedMessage Wire Object
	toData := &wire.SignedMessage{
		Data:        s.Data,
		Signature:   s.Signature,
		SigningFunc: s.SigningFunc,
	}
	// Marshal it to bytes
	bytes, err := proto.Marshal(toData)
	if err != nil {
		return nil, err
	}

	// Encrypt the Message using HybridEncryption
	key, cipher, err := crypto.HybridEncryption(addr.EncryptionKey, bytes)
	if err != nil {
		return nil, err
	}

	// Save all of this to an EncryptedMessage
	encryptionMessage := &EncryptedMessage{
		Data:           cipher,
		EncryptionKey:  key,
		EncryptionType: crypto.EncryptionRSA,
		To:             addr,
	}
	return encryptionMessage, nil
}

func (s *SignedMessage) UnencryptedMessage(addr *identity.Address) (*EncryptedMessage, error) {
	// Create a SignedMessage Wire Object
	toData := &wire.SignedMessage{
		Data:        s.Data,
		Signature:   s.Signature,
		SigningFunc: s.SigningFunc,
	}
	// Marshal it to bytes
	bytes, err := proto.Marshal(toData)
	if err != nil {
		return nil, err
	}

	// Save all of this to an EncryptedMessage
	encryptionMessage := &EncryptedMessage{
		Data:           bytes,
		EncryptionKey:  []byte{0},
		EncryptionType: crypto.EncryptionNone,
		To:             addr,
	}
	return encryptionMessage, nil

}

// Verify that a signed message is genuine
//
// Unwinds the R and S values of the ECDSA keypair from the Airdispatch Signature
// then passes them to the verifyPayload function.
func (sm *SignedMessage) Verify() bool {
	// Hash the data
	hash := crypto.HashSHA(sm.Data)

	for _, signature := range sm.Signature {
		// Create an ECDSA Key from the Bytes
		key, err := crypto.BytesToKey(signature.SigningKey)
		if err != nil {
			return false
		}

		// Reconstruct the Signature
		var r, s *big.Int = new(big.Int), new(big.Int)
		r.SetBytes(signature.GetR())
		s.SetBytes(signature.GetS())

		if !crypto.VerifyPayload(key, hash, r, s) {
			return false
		}
	}

	// Verify the bytes
	return true
}

type EncryptedMessage struct {
	Data           []byte
	EncryptionKey  []byte
	EncryptionType []byte
	To             *identity.Address
}

// This Function sends an Encrypted Message to a Server via a Router
func (e *EncryptedMessage) Send() error {
	conn, err := ConnectToServer(e.To.Location)
	if err != nil {
		return err
	}
	defer conn.Close()

	return e.SendMessageToConnection(conn)
}

// This function Decrypts an EncryptedMessage into a SignedMessage
func (e *EncryptedMessage) Decrypt(id *identity.Identity) (*SignedMessage, error) {
	if bytes.Equal(e.EncryptionType, crypto.EncryptionNone) {
		return e.UnencryptedMessage()
	}

	// Decrypt the data from the cipher.
	p, err := crypto.HybridDecryption(id.EncryptionKey, e.EncryptionKey, e.Data)
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

func (e *EncryptedMessage) UnencryptedMessage() (*SignedMessage, error) {
	if !bytes.Equal(e.EncryptionType, crypto.EncryptionNone) {
		return nil, errors.New("Unable to decrypt message without key.")
	}

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

func CreateEncryptedMessageFromBytes(theBytes []byte) (*EncryptedMessage, error) {
	downloadedMessage := &wire.EncryptedMessage{}
	err := proto.Unmarshal(theBytes, downloadedMessage)
	if err != nil {
		return nil, err
	}

	output := &EncryptedMessage{}

	output.Data = downloadedMessage.GetData()
	output.EncryptionKey = downloadedMessage.GetKey()
	output.EncryptionType = downloadedMessage.GetEncFunc()
	output.To = identity.CreateAddressFromBytes(downloadedMessage.GetToAddr())
	return output, nil
}

// TODO: `Sign` Message
