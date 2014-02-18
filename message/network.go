package message

import (
	"airdispat.ch/wire"
	"bytes"
	"encoding/binary"
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

func prefixBytes(data []byte) []byte {
	if data == nil {
		return nil
	}

	var length = int32(len(data))
	lengthBuf := &bytes.Buffer{}
	binary.Write(lengthBuf, binary.BigEndian, length)
	fullBuffer := bytes.Join([][]byte{wire.Prefix, lengthBuf.Bytes(), data}, nil)
	return fullBuffer
}
