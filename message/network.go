package message

import (
	"airdispat.ch/wire"
	"net"
)

func ConnectToServer(remote string) (net.Conn, error) {
	address, err := net.ResolveTCPAddr("tcp", remote)
	if err != nil {
		return nil, err
	}

	// Connect to the Remote Mail Server
	conn, err := net.DialTCP("tcp", nil, address)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func ReadMessageFromConnection(conn net.Conn) (*EncryptedMessage, error) {
	totalBytes, err := wire.ReadBytes(conn)
	if err != nil {
		return nil, err
	}

	theMessage, err := CreateEncryptedMessageFromBytes(totalBytes)
	if err != nil {
		return nil, err
	}

	return theMessage, nil
}
