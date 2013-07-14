package common

import (
	"airdispat.ch/airdispatch"
	"crypto/ecdsa"
	"net"
	"bytes"
	"io"
	"encoding/binary"
	"errors"
	"code.google.com/p/goprotobuf/proto"
)

const (
	REGISTRATION_MESSAGE = "REG"
	QUERY_MESSAGE = "QUE"
	QUERY_RESPONSE_MESSAGE = "RES"
	ALERT_MESSAGE = "ALE"
	RETRIEVAL_MESSAGE = "RET"
	SEND_REQUEST = "SEN"
	MAIL_MESSAGE = "MAI"
	ARRAY_MESSAGE = "ARR"
)

func MESSAGE_PREFIX() []byte {
	return []byte("AD")
}

func RETRIEVAL_TYPE_NORMAL() []byte { return []byte{0, 0} }
func RETRIEVAL_TYPE_PUBLIC() []byte { return []byte{0, 1} }
func RETRIEVAL_TYPE_MINE() []byte { return []byte{0, 2} }

func ReadTotalMessage(conn net.Conn) (unmarshalledData []byte, signedMessage []byte, mesType string, addr string, returnErr error) {
	// Read in the Sent Message
	totalBytes, err := ReadAirdispatchMessage(conn)
	if err != nil {
		return nil, nil, "", "", err
	}

	payload, mesType, addr, err := ReadSignedBytes(totalBytes)
	if err != nil {
		return nil, nil, "", "", err
	}

	// Return all of the data
	return payload, totalBytes, mesType, addr, nil
}

func ReadSignedBytes(theData []byte) (payload []byte, mesType string, addr string, returnErr error) {
	// Get the Signed Message
	downloadedMessage := &airdispatch.SignedMessage{}
	err := proto.Unmarshal(theData, downloadedMessage)
	if err != nil {
		return nil, "", "", err
	}

	// Verify that the address of the message is not spoofed
	if !VerifySignedMessage(downloadedMessage) {
		return nil, "", "", errors.New("Message is not signed properly. Discarding.")
	}

	// Determine the sending Address of the Message and the Message Type
	messageType := downloadedMessage.GetMessageType()
	keyByte, err := BytesToKey(downloadedMessage.SigningKey)
	if err != nil {
		return nil, "", "", err
	}

	theAddress := StringAddress(keyByte)

	return downloadedMessage.Payload, messageType, theAddress, nil
}

func ReadSignedMessage(conn net.Conn) (data []byte, mesType string, addr string, returnErr error) {
	data, _, mesType, addr, returnErr = ReadTotalMessage(conn)
	return
}

func ReadAirdispatchMessage(conn net.Conn) ([]byte, error) {
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
			if !bytes.Equal(prefixBuffer[0:2], MESSAGE_PREFIX()) {
				return nil, errors.New("Message is not for airdispatch...")
			}

			// The following four bytes contain the length of the message.
			binary.Read(bytes.NewBuffer(prefixBuffer[2:]), binary.BigEndian, &length)
			started = true

			// Added the Ability to Catch 0-Length Messages
			if length == 0 {
				err := errors.New("Cannot read a message with no content.")
				return nil, err
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

	if string(totalBytes)[:4] == "ERR:" {
		// This is not a regular message, but an error message. Ruh roh.
		return nil, errors.New(string(totalBytes))
	}

	// The data may contain extra 0s, we trim it to the lenght of the message here
	return totalBytes[0:length], nil
}

func GenerateSignature(key *ecdsa.PrivateKey, payload []byte) (*airdispatch.Signature, error) {
	r, s, err := signPayload(key, payload)
	if err != nil {
		return nil, err
	}

	newSignature := &airdispatch.Signature {
		R: r.Bytes(),
		S: s.Bytes(),
	}
	return newSignature, nil
}

func CreateSignedMessage(key *ecdsa.PrivateKey, data []byte, mesType string) (*airdispatch.SignedMessage, error) {
	hash := HashSHA(nil, data)
	newSignature, err := GenerateSignature(key, hash)
	if err != nil {
		return nil, err
	}

	newSignedMessage := &airdispatch.SignedMessage {
		Payload: data,
		Signature: newSignature,
		SigningKey: KeyToBytes(&key.PublicKey),
		MessageType: &mesType,
	}
	return newSignedMessage, nil
}

func CreatePrefixedMessage(data []byte) []byte {
	var prefix = MESSAGE_PREFIX() 
	var length = int32(len(data))
	lengthBuf := &bytes.Buffer{}
	binary.Write(lengthBuf, binary.BigEndian, length)
	fullBuffer := bytes.Join([][]byte{prefix, lengthBuf.Bytes(), data}, nil)
	return fullBuffer
}

func CreateAirdispatchMessage(data []byte, key *ecdsa.PrivateKey, mesType string) ([]byte, error) {
	newSignedMessage, err := CreateSignedMessage(key, data, mesType)
	if err != nil {
		return nil, err
	}

	signedData, err := proto.Marshal(newSignedMessage)
	if err != nil {
		return nil, err
	}

	toSend := CreatePrefixedMessage(signedData)
	return toSend, nil
}

func CreateArrayedMessage(itemLength uint32, key *ecdsa.PrivateKey) ([]byte, error) {
	newArray := &airdispatch.ArrayedData{
		NumberOfMessages: &itemLength,
	}
	dataArray, err := proto.Marshal(newArray)
	if err != nil {
		return nil, err
	}
	
	return CreateAirdispatchMessage(dataArray, key, ARRAY_MESSAGE)
}

func CreateErrorMessage(error string) []byte {
	return CreatePrefixedMessage([]byte("ERR:" + error))
}
