package common

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/gob"
	"io"
	"math/big"
	"os"
)

// Keygen Variables
type encodedECDSAKey struct {
	D, X, Y *big.Int
}

type encodedRSAKey struct {
	D, N *big.Int
	P    []*big.Int
	E    int
}

type encodedADKey struct {
	ECDSA *encodedECDSAKey
	RSA   *encodedRSAKey
}

// This function writes a Gob-Encoded ADKey to a buffer
func (a *ADKey) GobEncodeKey(buffer io.Writer) (io.Writer, error) {
	// Encode Signature Key
	ecdsaKey := a.SignatureKey
	eECDSAKey := &encodedECDSAKey{ecdsaKey.D, ecdsaKey.PublicKey.X, ecdsaKey.PublicKey.Y}

	// Encode Encryption Keys
	rsaKey := a.EncryptionKey
	eRSAKey := &encodedRSAKey{rsaKey.D, rsaKey.PublicKey.N, rsaKey.Primes, rsaKey.PublicKey.E}

	eADKey := encodedADKey{eECDSAKey, eRSAKey}

	enc := gob.NewEncoder(buffer)
	err := enc.Encode(eADKey)
	if err != nil {
		return nil, err
	}
	return buffer, nil
}

// This function loads a Gob-Encoded ADKey from a buffer
func GobDecodeKey(buffer io.Reader) (*ADKey, error) {
	decodedKey := &encodedADKey{}

	// Create the decoder
	dec := gob.NewDecoder(buffer)
	// Load from the File
	err := dec.Decode(&decodedKey)
	if err != nil {
		return nil, err
	}

	// Create the ECDSA Key from the Encoded Values
	newECDSAPublicKey := ecdsa.PublicKey{ADEllipticCurve, decodedKey.ECDSA.X, decodedKey.ECDSA.Y}
	newECDSAKey := ecdsa.PrivateKey{
		PublicKey: newECDSAPublicKey,
		D:         decodedKey.ECDSA.D,
	}

	// Create the RSA Key from the Encoded Values
	newRSAPublicKey := rsa.PublicKey{decodedKey.RSA.N, decodedKey.RSA.E}
	newRSAKey := rsa.PrivateKey{
		PublicKey: newRSAPublicKey,
		D:         decodedKey.RSA.D,
		Primes:    decodedKey.RSA.P,
	}

	// Reconstruct the Whole Key
	newADKey := &ADKey{
		SignatureKey:  &newECDSAKey,
		EncryptionKey: &newRSAKey,
	}

	return newADKey, nil
}

// This function Loads an Airdispatch Key from a File
func LoadKeyFromFile(filename string) (*ADKey, error) {
	// Open the File for Loading
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	return GobDecodeKey(file)
}

// This function Saves an Airdispatch Key to a File
func (a *ADKey) SaveKeyToFile(filename string) error {
	// Create the File to Store the Keys in
	file, err := os.Create(filename)
	if err != nil {
		return err
	}

	_, err = a.GobEncodeKey(file)
	if err != nil {
		return err
	}

	return nil
}
