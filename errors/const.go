package errors

import (
	"errors"
)

// These constants declare different Error Codes
type Code uint32

const (
	InvalidSignature Code = 1
	NoMessages       Code = 2
	NotAuthorized    Code = 3
	AddressNotFound  Code = 4
	MessageNotFound  Code = 5
	UnexpectedError  Code = 6
	InternalError    Code = 7
)

var ADSigningError = errors.New("ADSigningError: Message is not properly signed.")
var ADUnmarshallingError = errors.New("ADUnmarshallingError: Message could not be unmarshalled.")
var ADTimeoutError = errors.New("ADTimeoutError: Operation was not able to be completed in the timeout period")

var ADUnexpectedMessageTypeError = errors.New("ADUnexpectedMessageTypeError: Received a different type of message than expected.")

var ADTrackerVerificationError = errors.New("ADTrackerVerificationError: Could not verify the tracker is who you should be talking to.")
var ADTrackerListQueryError = errors.New("ADTrackerListQueryError: The address queried for could not be located in the tracker list provided.")

var ADDecryptionError = errors.New("ADDecryptionError: The payload of the Mail cannot be decrypted because the ADKey was not passed in correctly.")

var ADIncorrectParameterError = errors.New("ADIncorrectParameterError: One of the parameters of this function is out of bounds.")
