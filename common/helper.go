package common

import (
	"airdispat.ch/airdispatch"
	"crypto/ecdsa"
)

func CreateSignedMessage(key *ecdsa.PrivateKey, data []byte, mesType string) (*airdispatch.SignedMessage, error) {
	hash := HashSHA(nil, data)
	newSignature, err := GenerateSignature(key, hash)
	newSignedMessage := &airdispatch.SignedMessage {
		Payload: data,
		Signature: newSignature,
		SigningKey: KeyToBytes(&key.PublicKey),
		MessageType: &mesType,
	}
	return newSignedMessage, err
}
