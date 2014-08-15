package message

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	"airdispat.ch/crypto"
	"airdispat.ch/identity"
	"airdispat.ch/routing"
	"airdispat.ch/wire"
	"code.google.com/p/goprotobuf/proto"
)

// SignedMessage represents a chunk of data that has been signed by a user
// of AirDispatch.
type SignedMessage struct {
	Data            []byte
	Signature       []*wire.Signature
	SigningFunc     []byte
	verifiedAddress []string
}

// SignMessage will sign an object that implements the message interface with an
// id and return the corresponding SignedMessage.
func SignMessage(m Message, id *identity.Identity) (*SignedMessage, error) {
	messageType := m.Type()

	toData := &wire.Container{
		Header: m.Header().toWire(),
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

// AddSignature will add a new signature of the data by id onto the message.
// This is useful if you need a SignedMessage to be signed by multiple parties.
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

// ReconstructMessage will take the signed chunk of data and return
// the data, the messageType, the header on the data, and any errors.
//
// Additionally, it will ensure that the Header.From field matches one of the
// signatures verified during Verify().
func (s *SignedMessage) ReconstructMessage() (data []byte, messageType string, header Header, err error) {
	return s.reconstructMessage(false)
}

// ReconstructMessageWithTimestamp will do the same thing as ReconstructMessage
// but it will ensure that the timestamp is within the last five minutes.
func (s *SignedMessage) ReconstructMessageWithTimestamp() (data []byte, messageType string, header Header, err error) {
	return s.reconstructMessage(true)
}

func (s *SignedMessage) reconstructMessage(ts bool) (data []byte, messageType string, header Header, err error) {
	if s.verifiedAddress == nil {
		err = errors.New("Can't reconstruct message before verifying it.")
		return
	}

	unmarshaller := &wire.Container{}
	err = proto.Unmarshal(s.Data, unmarshaller)
	if err != nil {
		return
	}

	messageType = unmarshaller.GetType()
	data = unmarshaller.GetData()
	header, err = createHeaderFromWire(unmarshaller.GetHeader())
	if err != nil {
		return
	}

	verified := false
	for _, v := range s.verifiedAddress {
		if header.From.String() == v {
			verified = true
			break
		}
	}
	if !verified {
		return nil, "", Header{}, errors.New("Can't reconstruct message without a valid header.")
	}

	if ts {
		if header.Timestamp < time.Now().Unix()-600 ||
			header.Timestamp > time.Now().Unix()+600 {
			fmt.Errorf("Couldn't verify timestamp. Now: %d, Got: %d", time.Now().Unix(), header.Timestamp)
		}
	}

	return
}

// Encrypt will take an address string and a router, and encrypt the message
// with the key received. This is generally not used, as the application
// should lookup the key itself based on the routing.LookupType needed.
func (s *SignedMessage) Encrypt(addr string, router routing.Router) (*EncryptedMessage, error) {
	fullAddress, err := router.Lookup(addr, routing.LookupTypeDEFAULT)
	if err != nil {
		return nil, err
	}

	return s.EncryptWithKey(fullAddress)
}

// EncryptWithKey will take an *identity.Address that already has a key associated with it
// and encrypt the SignedMessage with it.
func (s *SignedMessage) EncryptWithKey(addr *identity.Address) (*EncryptedMessage, error) {
	if addr.IsPublic() {
		return s.UnencryptedMessage(addr)
	} else if addr.EncryptionKey == nil {
		return nil, errors.New("Cannot encrypt without encryption key.")
	}

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
	cipher, unencryptedKey, err := crypto.EncryptDataWithRandomAESKey(bytes)
	if err != nil {
		return nil, err
	}

	// Save all of this to an EncryptedMessage
	encryptionMessage := &EncryptedMessage{
		Data:           cipher,
		unencryptedKey: unencryptedKey,
	}
	err = encryptionMessage.AddRecipient(addr)

	return encryptionMessage, err
}

// UnencryptedMessage will take a signed message and an address and turn it into
// an "EncryptedMessage" to send on the wire without actually encrypting the data.
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
		Data: bytes,
	}
	return encryptionMessage, nil
}

// Verify that a signed message is genuine.
//
// Unwinds the R and S values of the ECDSA keypair from the Airdispatch Signature
// then passes them to the verifyPayload function.
//
// Additionally, it will save which addresses had signatures that were verified
// to match with Header{} verification later.
func (s *SignedMessage) Verify() bool {
	// Hash the data
	hash := crypto.HashSHA(s.Data)

	// Signed by nobody?
	if len(s.Signature) == 0 {
		return false
	}

	s.verifiedAddress = make([]string, len(s.Signature))
	for i, signature := range s.Signature {
		// Create an ECDSA Key from the Bytes
		key, err := crypto.BytesToKey(signature.SigningKey)
		if err != nil {
			return false
		}

		// Reconstruct the Signature
		var rSig, sSig *big.Int = new(big.Int), new(big.Int)
		rSig.SetBytes(signature.GetR())
		sSig.SetBytes(signature.GetS())

		if !crypto.VerifyPayload(key, hash, rSig, sSig) {
			return false
		}

		// Add fingerprint to signatures
		addr := &identity.Address{
			Fingerprint: crypto.BytesToAddress(signature.SigningKey),
		}
		s.verifiedAddress[i] = addr.String()
	}

	// Verify the bytes
	return true
}
