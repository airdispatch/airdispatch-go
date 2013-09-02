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

func ReadADMessage(conn net.Conn) (allData []byte, theMessage *ADMessagePrimative, returnErr error) {
	// Read in the Sent Message
	totalBytes, err := readADBytes(conn)
	if err != nil {
		return nil, nil, err
	}

	theMessage, err = ReadADMessageFromBytes(totalBytes)
	if err != nil {
		return nil, nil, err
	}

	// Return all of the data
	return totalBytes, theMessage, nil
}

func ReadADMessageFromBytes(theData []byte) (theMessage *ADMessagePrimative, returnErr error) {
	// Get the Signed Message
	downloadedMessage := &airdispatch.SignedMessage{}
	err := proto.Unmarshal(theData, downloadedMessage)
	if err != nil {
		return nil, err
	}

	// Verify that the address of the message is not spoofed
	if !VerifySignedMessage(downloadedMessage) {
		return nil, errors.New("Message is not signed properly. Discarding.")
	}

	theAddress := hexEncodeAddress(downloadedMessage.SigningKey)

	mesType := downloadedMessage.GetMessageType()

	if mesType == "ERR" {
		theError := downloadedMessage.Payload

		downloadedError := &airdispatch.Error{}
		err := proto.Unmarshal(theError, downloadedError)
		if err != nil {
			return nil, errors.New("Couldn't Unmarshal Error Message")
		}

		return nil, errors.New("Got Error Code " + *downloadedError.Code + " with description " + *downloadedError.Description)
	}

	completeMessage := &ADMessagePrimative{
		Payload:     downloadedMessage.Payload,
		MessageType: mesType,
		FromAddress: theAddress,
	}

	return completeMessage, nil
}

func readADBytes(conn net.Conn) ([]byte, error) {
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

func (a *ADKey) generateSignature(payload []byte) (*airdispatch.Signature, error) {
	r, s, err := signPayload(a.SignatureKey, payload)
	if err != nil {
		return nil, err
	}

	newSignature := &airdispatch.Signature{
		R: r.Bytes(),
		S: s.Bytes(),
	}
	return newSignature, nil
}

func AddPrefixToData(data []byte) []byte {
	var length = int32(len(data))
	lengthBuf := &bytes.Buffer{}
	binary.Write(lengthBuf, binary.BigEndian, length)
	fullBuffer := bytes.Join([][]byte{ADMessagePrefix, lengthBuf.Bytes(), data}, nil)
	return fullBuffer
}

func (a *ADKey) CreateADSignedMessage(message *ADMessagePrimative) (*airdispatch.SignedMessage, error) {
	hash := HashSHA(message.Payload)
	newSignature, err := a.generateSignature(hash)
	if err != nil {
		return nil, err
	}

	newSignedMessage := &airdispatch.SignedMessage{
		Payload:     message.Payload,
		Signature:   newSignature,
		SigningKey:  KeyToBytes(&a.SignatureKey.PublicKey),
		MessageType: &message.MessageType,
	}
	return newSignedMessage, nil
}

func (a *ADKey) CreateADMessage(message *ADMessagePrimative) ([]byte, error) {
	newSignedMessage, err := a.CreateADSignedMessage(message)
	if err != nil {
		return nil, err
	}

	signedData, err := proto.Marshal(newSignedMessage)
	if err != nil {
		return nil, err
	}

	toSend := AddPrefixToData(signedData)
	return toSend, nil
}

func (a *ADKey) CreateArrayedMessage(itemLength uint32) ([]byte, error) {
	newArray := &airdispatch.ArrayedData{
		NumberOfMessages: &itemLength,
	}
	dataArray, err := proto.Marshal(newArray)
	if err != nil {
		return nil, err
	}

	newMessage := &ADMessagePrimative{
		Payload:     dataArray,
		MessageType: ARRAY_MESSAGE,
	}

	return a.CreateADMessage(newMessage)
}

func (a *ADKey) CreateErrorMessage(code string, description string) []byte {
	newError := &airdispatch.Error{
		Code:        &code,
		Description: &description,
	}

	data, err := proto.Marshal(newError)
	if err != nil {
		// We're screwed.
		return nil
	}

	newMessage := &ADMessagePrimative{
		Payload:     data,
		MessageType: ERROR_MESSAGE,
	}

	toSend, err := a.CreateADMessage(newMessage)
	if err != nil {
		// Still screwed
		return nil
	}

	return toSend
}
