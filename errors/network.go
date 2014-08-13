package errors

import (
	"airdispat.ch/message"
	"airdispat.ch/wire"
	"io"
	"net"
)

func CheckConnectionForError(conn net.Conn) error {
	m, err := message.ReadMessageFromConnection(conn)
	if err == io.EOF {
		return nil
	}

	sin, err := m.UnencryptedMessage()
	if err != nil {
		return nil
	}

	if !sin.Verify() {
		return nil
	}

	d, mType, h, err := sin.ReconstructMessage()
	if err != nil {
		return nil
	}

	if mType != wire.ErrorCode {
		return nil
	}

	return CreateErrorFromBytes(d, h)
}
