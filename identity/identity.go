// The identity package has methods and structures relating
// to methods of identification on the AirDispatch network
// including Signing Keys, Encryption Keys, Address Fingerprints,
// and more!
package identity

import (
	"crypto/ecdsa"
	"crypto/rsa"
)

// The Identity structure is a complete AirDispatch user
// including Encryption and Signing private keys.
//
// WARNING: This structure should be stored carefully
// as having access to this data will be enough to
// impersonate someone on the AirDispatch network.
type Identity struct {
	Address       *Address
	EncryptionKey *rsa.PrivateKey
	SigningKey    *ecdsa.PrivateKey
}
