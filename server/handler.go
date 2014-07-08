package server

import (
	"airdispat.ch/message"
)

type Handler interface {
	HandlesType(typ string) bool
	HandleMessage(typ string, data []byte, h message.Header) (message.Message, error)
}
