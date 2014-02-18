package message

import (
	"airdispat.ch/wire"
	"code.google.com/p/goprotobuf/proto"
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

func (e *EncryptedMessage) SendMessageToConnection(conn net.Conn) error {
	// The first step to sending the message is marshalling it to bytes.
	toData := &wire.EncryptedMessage{
		Data:    e.Data,
		ToAddr:  e.To.Fingerprint,
		Key:     e.EncryptionKey,
		EncFunc: e.EncryptionType,
	}
	bytes, err := proto.Marshal(toData)
	if err != nil {
		return err
	}

	conn.Write(wire.PrefixBytes(bytes))
	return nil
}
