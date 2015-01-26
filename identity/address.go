package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/gob"
	"encoding/hex"

	"airdispat.ch/crypto"
)

// The address structure provides abstractions on
// AirDispatch addresses
type Address struct {
	// The fingerprint of the address signingKey
	Fingerprint []byte
	// The location of the user's server
	Location string
	// The publicKey of the user
	EncryptionKey *rsa.PublicKey
	// The signingKey of the user
	SigningKey *ecdsa.PublicKey

	// Optional Alias of the Address
	Alias string

	public bool
	cached bool
}

// The Public variable has an address that can represent
// sending a message to the public.
var Public *Address = &Address{
	public: true,
}

func (a *Address) generateFingerprint() {
	by := crypto.KeyToBytes(a.SigningKey)
	a.Fingerprint = crypto.BytesToAddress(by)
}

// The string representation of an Address is just
// the Fingerprint of that address.
func (a *Address) String() string {
	return hex.EncodeToString(a.Fingerprint)
}

// Compares the Address to the `Public Address`.
func (a *Address) IsPublic() bool {
	return (a == Public)
}

func (a *Address) HasLocation() bool {
	return a.cached
}

func (a *Address) CanSend() bool {
	return a.EncryptionKey != nil
}

func (a *Address) EqualsBytes(addr []byte) bool {
	return hex.EncodeToString(addr) == a.String()
}

func CreateAddressFromBytes(b []byte) *Address {
	return &Address{
		Fingerprint: b,
		cached:      false,
	}
}

func CreateAddressFromString(addr string) *Address {
	by, err := hex.DecodeString(addr)
	if err != nil {
		return nil
	}
	return CreateAddressFromBytes(by)
}

// Encoding for Addresses for easy serialization.

type encodedAddress struct {
	Encryption []byte
	Signing    []byte
	Location   string
	Alias      string
}

func (a *Address) Encode() ([]byte, error) {
	rsa := crypto.RSAToBytes(a.EncryptionKey)
	ecdsa := crypto.KeyToBytes(a.SigningKey)

	b := &bytes.Buffer{}
	if err := gob.NewEncoder(b).Encode(&encodedAddress{
		Encryption: rsa,
		Signing:    ecdsa,
		Location:   a.Location,
		Alias:      a.Alias,
	}); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func DecodeAddress(b []byte) (*Address, error) {
	output := &encodedAddress{}
	if err := gob.NewDecoder(bytes.NewBuffer(b)).Decode(output); err != nil {
		return nil, err
	}

	rsa, err := crypto.BytesToRSA(output.Encryption)
	if err != nil {
		return nil, err
	}

	ecdsa, err := crypto.BytesToKey(output.Signing)
	if err != nil {
		return nil, err
	}

	return &Address{
		EncryptionKey: rsa,
		SigningKey:    ecdsa,
		Location:      output.Location,
		Alias:         output.Alias,
	}, nil
}
