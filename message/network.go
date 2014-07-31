package message

import (
	"net"

	"airdispat.ch/identity"
	"airdispat.ch/wire"
	"code.google.com/p/goprotobuf/proto"
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

func SendMessageAndReceiveWithoutTimestamp(m Message, sender *identity.Identity, addr *identity.Address) ([]byte, string, Header, error) {
	return sendMessageAndReceive(m, sender, addr, false)
}
func SendMessageAndReceive(m Message, sender *identity.Identity, addr *identity.Address) ([]byte, string, Header, error) {
	return sendMessageAndReceive(m, sender, addr, true)
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

	return msg.Reconstruct(sender, ts)
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
	bytes, err := e.ToBytes()
	if err != nil {
		return err
	}

	conn.Write(wire.PrefixBytes(bytes))
	return nil
}

func (e *EncryptedMessage) ToBytes() ([]byte, error) {
	// The first step to sending the message is marshalling it to bytes.
	toAddr := []byte{0}
	if e.To != nil && !e.To.IsPublic() {
		toAddr = e.To.Fingerprint
	}

	toData := &wire.EncryptedMessage{
		Data:    e.Data,
		ToAddr:  toAddr,
		Key:     e.EncryptionKey,
		EncFunc: e.EncryptionType,
	}
	return proto.Marshal(toData)
}
