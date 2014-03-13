// The identity package has methods and structures relating
// to methods of identification on the AirDispatch network
// including Signing Keys, Encryption Keys, Address Fingerprints,
// and more!
package identity

import (
	"airdispat.ch/crypto"
	"airdispat.ch/wire"
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

// This creates a new random, AirDispatch Identity
func CreateIdentity() (id *Identity, err error) {
	key := &Identity{}

	// Create Signing Key
	key.SigningKey, err = ecdsa.GenerateKey(crypto.EllipticCurve, crypto.Random)
	if err != nil {
		return nil, err
	}

	key.EncryptionKey, err = rsa.GenerateKey(crypto.Random, 2048)
	if err != nil {
		return nil, err
	}
	key.PopulateAddress()

	return key, err
}

// This function signs a series of bytes
func (a *Identity) SignBytes(payload []byte) (*wire.Signature, error) {
	r, s, err := crypto.SignPayload(a.SigningKey, payload)
	if err != nil {
		return nil, err
	}

	newSignature := &wire.Signature{
		R: r.Bytes(),
		S: s.Bytes(),
	}
	return newSignature, nil
}

func (a *Identity) SetLocation(newLocation string) {
	a.Address.Location = newLocation
}

func (a *Identity) PopulateAddress() {
	a.Address = &Address{
		EncryptionKey: &a.EncryptionKey.PublicKey,
		SigningKey:    &a.SigningKey.PublicKey,
	}
	a.Address.generateFingerprint()
}
