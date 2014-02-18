package errors

import (
	"airdispat.ch/message"
)

type Error struct {
	Code        int
	Description string
}

// These constants declare different Error Codes
const (
	AddressNotFound  int = 4
	MessageNotFound  int = 4
	InvalidSignature int = 1
	NoMessages       int = 2
	NotAuthorized    int = 4
)

var ADSigningError = errors.New("ADSigningError: Message is not properly signed.")
var ADUnmarshallingError = errors.New("ADUnmarshallingError: Message could not be unmarshalled.")
var ADTimeoutError = errors.New("ADTimeoutError: Operation was not able to be completed in the timeout period")

var ADUnexpectedMessageTypeError = errors.New("ADUnexpectedMessageTypeError: Received a different type of message than expected.")

var ADTrackerVerificationError = errors.New("ADTrackerVerificationError: Could not verify the tracker is who you should be talking to.")
var ADTrackerListQueryError = errors.New("ADTrackerListQueryError: The address queried for could not be located in the tracker list provided.")

var ADDecryptionError = errors.New("ADDecryptionError: The payload of the Mail cannot be decrypted because the ADKey was not passed in correctly.")

var ADIncorrectParameterError = errors.New("ADIncorrectParameterError: One of the parameters of this function is out of bounds.")
