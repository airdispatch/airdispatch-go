package identity

import (
	"airdispat.ch/crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/hex"
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