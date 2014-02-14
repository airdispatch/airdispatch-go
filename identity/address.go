package identity

import (
	"crypto/ecdsa"
	"crypto/rsa"
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
}

// The Public variable has an address that can represent
// sending a message to the public.
var Public *Address = &Address{
	public: true,
}

// The string representation of an Address is just
// the Fingerprint of that address.
func (a *Address) String() string {
	return a.Fingerprint
}

// Compares the Address to the `Public Address`.
func (a *Address) IsPublic() bool {
	return (a == ADPublicAddress)
}
