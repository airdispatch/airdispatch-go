package message

import (
	"airdispat.ch/crypto"
	"airdispat.ch/identity"
	"airdispat.ch/routing"
	"airdispat.ch/wire"
	"code.google.com/p/goprotobuf/proto"
	"math/big"
)

type Message interface {
	Header() Header
	Type() string
	ToBytes() []byte
}

func SignMessage(m Message, id *identity.Identity) (*SignedMessage, error) {
	messageType := m.Type()

	toData := &wire.Container{
		Header: m.Header().ToWire(),
		Data:   m.ToBytes(),
		Type:   &messageType,
	}
	toSign, err := proto.Marshal(toData)
	if err != nil {
		return nil, err
	}

	r, s, err := crypto.SignPayload(id.SigningKey, toSign)
	if err != nil {
		return nil, err
	}

	newSignature := &wire.Signature{
		R: r.Bytes(),
		S: s.Bytes(),
	}

	newSignedMessage := &SignedMessage{
		Data:        toSign,
		Signature:   newSignature,
		SigningFunc: crypto.SigningECDSA,
		SigningKey:  crypto.KeyToBytes(&id.SigningKey.PublicKey),
	}
	return newSignedMessage, nil
}

// Common AirDispatch Header
type Header struct {
	From      *identity.Address
	To        *identity.Address
	Timestamp int64
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
	return &wire.Header{
		FromAddr:  h.From.Fingerprint,
		ToAddr:    h.To.Fingerprint,
		Timestamp: &time,
	}
}

// Container Message for Signed Data
type SignedMessage struct {
	Data        []byte
	Signature   *wire.Signature
	SigningKey  []byte
	SigningFunc []byte
}

func (s *SignedMessage) ReconstructMessage() (data []byte, messageType string, header Header, err error) {
	var unmarshaller *wire.Container
	err = proto.Unmarshal(s.Data, unmarshaller)
	if err != nil {
		return
	}

	messageType = unmarshaller.GetType()
	data = unmarshaller.GetData()
	header = CreateHeaderFromWire(unmarshaller.GetHeader())

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
		SigningKey:  s.SigningKey,
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

// Verify that a signed message is genuine
//
// Unwinds the R and S values of the ECDSA keypair from the Airdispatch Signature
// then passes them to the verifyPayload function.
func (sm *SignedMessage) Verify() bool {
	// Hash the data
	hash := crypto.HashSHA(sm.Data)

	// Create an ECDSA Key from the Bytes
	key, err := crypto.BytesToKey(sm.SigningKey)
	if err != nil {
		return false
	}

	// Reconstruct the Signature
	var r, s *big.Int = new(big.Int), new(big.Int)
	r.SetBytes(sm.Signature.GetR())
	s.SetBytes(sm.Signature.GetS())

	// Verify the bytes
	return crypto.VerifyPayload(key, hash, r, s)
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
	// Decrypt the data from the cipher.
	p, err := crypto.HybridDecryption(id.EncryptionKey, e.EncryptionKey, e.Data)
	if err != nil {
		return nil, err
	}

	// Unmarshal the wire data
	var x *wire.SignedMessage
	err = proto.Unmarshal(p, x)
	if err != nil {
		return nil, err
	}

	// Create a signedmessage
	sm := &SignedMessage{
		Data:        x.GetData(),
		Signature:   x.GetSignature(),
		SigningKey:  x.GetSigningKey(),
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
