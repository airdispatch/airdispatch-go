package message

import (
	"net"

	"airdispat.ch/identity"
	"airdispat.ch/wire"
)

// ConnectToServer is a convenience method that attempts to dial a tcp connection
// to a server specified by a string.
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

// SendMessageAndReceive does exactly what you think:
//
// - Signs, Encrypts, and sends a message to a connection
// - Receives, Decrypts, Verifies, and Reconstructs a message from a connection
// (without timestamp support)
func SendMessageAndReceive(m Message, sender *identity.Identity, addr *identity.Address) ([]byte, string, Header, error) {
	return sendMessageAndReceive(m, sender, addr, false)
}

// SendMessageAndReceiveWithTimestamp does exactly the same as SendMessageAndReceive
// but includes timestamp support.
func SendMessageAndReceiveWithTimestamp(m Message, sender *identity.Identity, addr *identity.Address) ([]byte, string, Header, error) {
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

// ReadMessageFromConnection will return a read EncryptedMessage off a specified
// net.Conn.
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

// SendMessageToConnection will send an encryptedMessage to a connection.
func (e *EncryptedMessage) SendMessageToConnection(conn net.Conn) error {
	bytes, err := e.ToBytes()
	if err != nil {
		return err
	}

	conn.Write(wire.PrefixBytes(bytes))
	return nil
}
