package message

import (
	"airdispat.ch/identity"
	"airdispat.ch/wire"
	"code.google.com/p/goprotobuf/proto"
	"errors"
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

func SendMessageAndReceiveWithoutTimestamp(m Message, sedner *identity.Identity, addr *identity.Address) ([]byte, string, Header, error) {
	return sendMessageAndReceive(m, sneder, addr, false)
}
func SendMessageAndReceive(m Message, sender *identity.Identity, addr *identity.Address) ([]byte, string, Header, error) {
	return sendMessageAndReceive(m, sneder, addr, true)
}

func sendMessageAndReceive(m Message, sender *identity.Identity, addr *identity.Address, ts bool) ([]byte, string, Header, error) {
	signed, err := SignMessage(m, sender)
	if err != nil {
		return nil, "", Header{}, err
	}

	enc, err := signed.EncryptWithKey(addr)
	if err != nil {
		return nil, "", Header{}, err
	}

	conn, err := ConnectToServer(addr.Location)
	if err != nil {
		return nil, "", Header{}, err
	}
	defer conn.Close()

	err = enc.SendMessageToConnection(conn)
	if err != nil {
		return nil, "", Header{}, err
	}

	msg, err := ReadMessageFromConnection(conn)
	if err != nil {
		return nil, "", Header{}, err
	}

	receivedSign, err := msg.Decrypt(sender)
	if err != nil {
		return nil, "", Header{}, err
	}

	if !receivedSign.Verify() {
		return nil, "", Header{}, errors.New("Unable to Verify Message")
	}

	if ts {
		return receivedSign.ReconstructMessage()
	} else {
		return receivedSign.ReconstructMessageWithoutTimestamp()
	}
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
