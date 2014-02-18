package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"time"
)

// This variable represents the prefix that is common to all Airdispatch messages.
var ADMessagePrefix = []byte("AD")

var ADRetrievalMine = []byte{0, 2}   // The bytes that represent a 'Mine' Retrieval Type
var ADRetrievalNormal = []byte{0, 0} // The bytes that represent a 'Normal' Retrieval Type
var ADRetrievalPublic = []byte{0, 1} // The bytes that represent a 'Public' Retrieval Type

// This type is used to determine how to handle an Airdispatch Address.
type AirdispatchAddressType int

// The 'Normal' Airdispatch Address, represented by a hashed public ECDSA key.
var AirdispatchAddressNormal AirdispatchAddressType = 1

// The 'Legacy' Airdispatch Address, represented by a user 'at' a tracking server.
var AirdispatchAddressLegacy AirdispatchAddressType = 2

// The 'Direct' Airdispatch Address, represented by a public key hash 'at' a mailserver.
var AirdispatchAddressDirect AirdispatchAddressType = 3

// This struct represents all the information needed to send and read messages sent
// to or form this address
type ADKey struct {
	SignatureKey  *ecdsa.PrivateKey
	EncryptionKey *rsa.PrivateKey
}

// ERRORS
var ADTimeoutSeconds time.Duration = 30
