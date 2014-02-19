// The wire package contains all of the Protocol Buffers
// source files and compiled go files. Additionally, it contains
// certain important constants for AirDispatch servers.
package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

var Prefix []byte = []byte("AD")

// The constants represent the three-letter codes that denote each type of
// Airdispatch message. The names of each constant should make the message
// that they each represent self-apparent.
const (
	MessageDescriptionCode  = "MDE"
	MessageListCode         = "MLI"
	TransferMessageCode     = "XFM"
	TransferMessageListCode = "XFL"
	MailCode                = "MAI"
	DataCode                = "DAT"
	ErrorCode               = "ERR"
)

func PrefixBytes(data []byte) []byte {
	if data == nil {
		return nil
	}

	var length = int32(len(data))
	lengthBuf := &bytes.Buffer{}
	binary.Write(lengthBuf, binary.BigEndian, length)
	fullBuffer := bytes.Join([][]byte{Prefix, lengthBuf.Bytes(), data}, nil)
	return fullBuffer
}

func ReadBytes(conn io.Reader) ([]byte, error) {
	// This Buffer will Store the Data Temporarily
	buf := &bytes.Buffer{}
	started := false
	var length int32

	for {

		// If this is the beginning of the message, we must take off the prefix.
		if !started {

			// Each Prefix is Six Bytes
			prefixBuffer := make([]byte, 6)

			// Read the Prefix
			_, err := io.ReadFull(conn, prefixBuffer)
			if err != nil {
				return nil, err
			}

			// The first two bytes should contain the standard message prefix.
			if !bytes.Equal(prefixBuffer[0:2], Prefix) {
				return nil, errors.New("Message is not for airdispatch...")
			}

			// The following four bytes contain the length of the message.
			binary.Read(bytes.NewBuffer(prefixBuffer[2:]), binary.BigEndian, &length)
			started = true

			// Added the Ability to Catch 0-Length Messages
			if length == 0 {
				return nil, errors.New("Cannot read a message with no content.")
			}
		}

		// We will read in data in chunks of the length of bytes
		data := make([]byte, length)
		_, err := io.ReadFull(conn, data)

		if err != nil {
			return nil, err
		}

		// Store the 256 read bytes
		buf.Write(data)

		// Stop reading if the buffer contains all of the data
		if int32(buf.Len()) >= length {
			break
		}

	}

	// All of the data is stored in the buffer
	totalBytes := buf.Bytes()

	// The data may contain extra 0s, we trim it to the lenght of the message here
	return totalBytes[0:length], nil
}
