package server

import (
	"net"

	"airdispat.ch/message"
)

type Handler interface {
	HandlesType(typ string) bool
	HandleMessage(typ string, data []byte, h message.Header, conn net.Conn) ([]message.Message, error)
}
