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
