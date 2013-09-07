package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"time"
)

var ADEllipticCurve elliptic.Curve = elliptic.P256()

// The constants represent the three-letter codes that denote each type of
// Airdispatch message. The names of each constant should make the message
// that they each represent self-apparent.
const (
	REGISTRATION_MESSAGE   = "REG"
	QUERY_MESSAGE          = "QUE"
	QUERY_RESPONSE_MESSAGE = "RES"
	ALERT_MESSAGE          = "ALE"
	RETRIEVAL_MESSAGE      = "RET"
	SEND_REQUEST           = "SEN"
	MAIL_MESSAGE           = "MAI"
	ARRAY_MESSAGE          = "ARR"
	ERROR_MESSAGE          = "ERR"
)

// This variable represents the prefix that is common to all Airdispatch messages.
var ADMessagePrefix = []byte("AD")

var ADRetrievalMine = []byte{0, 2}   // The bytes that represent a 'Mine' Retrieval Type
var ADRetrievalNormal = []byte{0, 0} // The bytes that represent a 'Normal' Retrieval Type
var ADRetrievalPublic = []byte{0, 1} // The bytes that represent a 'Public' Retrieval Type

var _privateADRSAPrefix = []byte("AD-RSA")
var _privateADECDSAPrefix = []byte{3}

// This type is used to determine how to handle an Airdispatch Address.
type AirdispatchAddressType int

// The 'Normal' Airdispatch Address, represented by a hashed public ECDSA key.
var AirdispatchAddressNormal AirdispatchAddressType = 1

// The 'Legacy' Airdispatch Address, represented by a user 'at' a tracking server.
var AirdispatchAddressLegacy AirdispatchAddressType = 2

// The 'Direct' Airdispatch Address, represented by a public key hash 'at' a mailserver.
var AirdispatchAddressDirect AirdispatchAddressType = 3

var ADEncryptionNone = "airdispat.ch/crypto/none"
var ADEncryptionRSA = "airdispat.ch/crypto/rsa2048-aes256"

// This struct represents all the information needed to send and read messages sent
// to or form this address
type ADKey struct {
	SignatureKey  *ecdsa.PrivateKey
	EncryptionKey *rsa.PrivateKey
}

// ERRORS
var ADSigningError = errors.New("ADSigningError: Message is not properly signed.")
var ADUnmarshallingError = errors.New("ADUnmarshallingError: Message could not be unmarshalled.")
var ADTimeoutError = errors.New("ADTimeoutError: Operation was not able to be completed in the timeout period")

var ADUnexpectedMessageTypeError = errors.New("ADUnexpectedMessageTypeError: Received a different type of message than expected.")

var ADTrackerVerificationError = errors.New("ADTrackerVerificationError: Could not verify the tracker is who you should be talking to.")
var ADTrackerListQueryError = errors.New("ADTrackerListQueryError: The address queried for could not be located in the tracker list provided.")

var ADDecryptionError = errors.New("ADDecryptionError: The payload of the Mail cannot be decrypted because the ADKey was not passed in correctly.")

var ADIncorrectParameterError = errors.New("ADIncorrectParameterError: One of the parameters of this function is out of bounds.")

var ADTimeoutSeconds time.Duration = 30

func ADReceivedError(code string, description string) error {
	return errors.New("ADReceivedError: " + code + " - " + description)
}
