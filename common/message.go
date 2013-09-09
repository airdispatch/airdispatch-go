package common

import (
	"airdispat.ch/airdispatch"
	"bytes"
	"code.google.com/p/goprotobuf/proto"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

type ADMessage struct {
	Payload     []byte
	MessageType string
	FromAddress *ADAddress
}

func CreateADMessageFromConnection(conn net.Conn) (*ADMessage, error) {
	totalBytes, err := readBytesFromConnection(conn)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	theMessage, err := CreateADMessageFromBytes(totalBytes)
	if err != nil {
		return nil, err
	}

	return theMessage, nil
}

func CreateADMessageFromBytes(theBytes []byte) (*ADMessage, error) {
	// Get the Signed Message
	downloadedMessage := &airdispatch.SignedMessage{}
	err := proto.Unmarshal(theBytes, downloadedMessage)
	if err != nil {
		return nil, err
	}

	// Verify that the address of the message is not spoofed
	if !VerifySignedMessage(downloadedMessage) {
		return nil, ADSigningError
	}

	theAddress := hexEncodeAddress(downloadedMessage.SigningKey)

	mesType := downloadedMessage.GetMessageType()

	if mesType == ERROR_MESSAGE {
		theError := downloadedMessage.Payload

		downloadedError := &airdispatch.Error{}
		err := proto.Unmarshal(theError, downloadedError)
		if err != nil {
			return nil, err
		}

		return nil, ADReceivedError(*downloadedError.Code, *downloadedError.Description)
	}

	output := &ADMessage{}

	output.MessageType = mesType
	output.Payload = downloadedMessage.GetPayload()

	output.FromAddress = CreateADAddress(theAddress)

	return output, nil
}

func (a *ADMessage) SendToAddress(addr *ADAddress, key *ADKey, trackerList *ADTrackerList) error {
	_, err := a.SendToAddressWithResponse(addr, key, trackerList)
	return err
}

func (a *ADMessage) SendToAddressWithResponse(addr *ADAddress, key *ADKey, trackerList *ADTrackerList) (*ADMessage, error) {
	loc, err := addr.GetLocation(key, trackerList)
	if err != nil {
		return nil, err
	}

	return a.SendToServerWithResponse(loc, key)
}

func (a *ADMessage) SendToServer(location string, key *ADKey) error {
	_, err := a.SendToServerWithResponse(location, key)
	return err
}

func (a *ADMessage) SendToServerWithResponse(location string, key *ADKey) (*ADMessage, error) {
	conn, err := ConnectToServer(location)
	if err != nil {
		return nil, err
	}

	defer conn.Close()

	err = a.SendToConnection(conn, key)
	if err != nil {
		return nil, err
	}

	output, err := CreateADMessageFromConnection(conn)
	if err != nil {
		return nil, err
	}

	return output, nil
}

func (a *ADMessage) SendToConnection(conn net.Conn, key *ADKey) error {
	// Hash the Message
	hash := HashSHA(a.Payload)

	// Sign the Bytes
	newSignature, err := key.SignBytes(hash)
	if err != nil {
		return err
	}

	// Create Signed Message Object
	newSignedMessage := &airdispatch.SignedMessage{
		Payload:     a.Payload,
		Signature:   newSignature,
		SigningKey:  KeyToBytes(&key.SignatureKey.PublicKey),
		MessageType: &a.MessageType,
	}

	// Marshal the Object
	signedData, err := proto.Marshal(newSignedMessage)
	if err != nil {
		return err
	}

	// Prefix the Data with the correct bytes
	var length = int32(len(signedData))
	lengthBuf := &bytes.Buffer{}
	binary.Write(lengthBuf, binary.BigEndian, length)
	fullBuffer := bytes.Join([][]byte{ADMessagePrefix, lengthBuf.Bytes(), signedData}, nil)

	conn.Write(fullBuffer)
	return nil
}

func readBytesFromConnection(conn net.Conn) ([]byte, error) {
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
			if !bytes.Equal(prefixBuffer[0:2], ADMessagePrefix) {
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

	// if string(totalBytes)[:4] == "ERR:" {
	// 	// This is not a regular message, but an error message. Ruh roh.
	// 	return nil, errors.New(string(totalBytes))
	// }

	// The data may contain extra 0s, we trim it to the lenght of the message here
	return totalBytes[0:length], nil
}

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

type ADAlert struct {
	*ADMessage
	ToAddress *ADAddress
	Location  string
	MessageID string
}

func CreateADAlertFromADMessage(message *ADMessage) (*ADAlert, error) {
	theAlert := &airdispatch.Alert{}
	err := proto.Unmarshal(message.Payload, theAlert)
	if err != nil {
		return nil, err
	}

	output := &ADAlert{message, CreateADAddress(theAlert.GetToAddress()), theAlert.GetLocation(), theAlert.GetMessageId()}

	return output, nil
}

func (a *ADAlert) GetMail() (*ADMail, error) {
	return nil, nil
}
