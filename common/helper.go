package common

import (
	"airdispat.ch/airdispatch"
	"crypto/ecdsa"
	"net"
	"bytes"
	"io"
	"encoding/binary"
	"fmt"
	"errors"
	"reflect"
	"code.google.com/p/goprotobuf/proto"
)

const (
	REGISTRATION_MESSAGE = "REG"
	QUERY_MESSAGE = "QUE"
	ALERT_MESSAGE = "ALE"
	RETRIEVAL_MESSAGE = "RET"
	SEND_REQUEST = "SEN"
)

func MESSAGE_PREFIX() []byte {
	return []byte("AD")
}

func ReadAsync(conn net.Conn, theChan chan []byte) {
	data, err := ReadAirdispatchMessage(conn) 
	if err != nil {
		fmt.Println("READ ERROR")
	}
	theChan <- data
}

func ReadAirdispatchMessage(conn net.Conn) ([]byte, error) {
	// This Buffer will Store the Data Temporarily
	buf := &bytes.Buffer{}
	started := false	
	var length int16

	for {

		// If this is the beginning of the message, we must take off the prefix.
		if !started {

			// Each Prefix is Two Bytes
			prefixBuffer := make([]byte, 4)
			io.ReadFull(conn, prefixBuffer)

			// The first two bytes should contain the standard message prefix.
			if !bytes.Equal(prefixBuffer[0:2], MESSAGE_PREFIX()) {
				fmt.Println("Not an Airdispat.ch Message")
				return nil, errors.New("message is not for airdispatch...")
			}

			// The following two bytes contain the length of the message.
			binary.Read(bytes.NewBuffer(prefixBuffer[2:]), binary.BigEndian, &length)
			started = true

			// Added the Ability to Catch 0-Length Messages
			if length == 0 {
				err := errors.New("Cannot read a message with no content.")
				fmt.Println(err)
				return nil, err
			}
		}

		// We will read in data in chunks of the length of bytes
		data := make([]byte, length)
		n, err := io.ReadFull(conn, data)

		// TODO: Change this to actually report a read error if it occured
		// Only report an error if it read in more data than was possible.
		if err != nil && n > len(data) {
			fmt.Println(err)
			fmt.Println("Unable to read from client!")
			return nil, err
		}

		// Store the 256 read bytes
		buf.Write(data)

		// Stop reading if the buffer contains all of the data
		if int16(buf.Len()) >= length {
			break
		}

	}

	// All of the data is stored in the buffer
	totalBytes := buf.Bytes()

	if string(totalBytes)[:4] == "ERR:" {
		// This is not a regular message, but an error message. Ruh roh.
		fmt.Println("Error Message Returned")
		fmt.Println(string(totalBytes))
		newErr := errors.New(string(totalBytes))
		return nil, newErr
	}

	// The data may contain extra 0s, we trim it to the lenght of the message here
	return totalBytes[0:length], nil
}

func GenerateSignature(key *ecdsa.PrivateKey, payload []byte) (*airdispatch.Signature, error) {
	r, s, err := Sign(key, payload)
	newSignature := &airdispatch.Signature {
		R: r.Bytes(),
		S: s.Bytes(),
	}
	return newSignature, err
}

func CreateSignedMessage(key *ecdsa.PrivateKey, data []byte, mesType string) (*airdispatch.SignedMessage, error) {
	hash := HashSHA(nil, data)
	newSignature, err := GenerateSignature(key, hash)
	newSignedMessage := &airdispatch.SignedMessage {
		Payload: data,
		Signature: newSignature,
		SigningKey: KeyToBytes(&key.PublicKey),
		MessageType: &mesType,
	}
	return newSignedMessage, err
}

func CreatePrefixedMessage(data []byte) []byte {
	var prefix = MESSAGE_PREFIX() 
	var length = int16(len(data))
	lengthBuf := &bytes.Buffer{}
	binary.Write(lengthBuf, binary.BigEndian, length)
	fullBuffer := bytes.Join([][]byte{prefix, lengthBuf.Bytes(), data}, nil)
	return fullBuffer
}

func CreateAirdispatchMessage(data []byte, key *ecdsa.PrivateKey, mesType string) []byte {
	newSignedMessage, _ := CreateSignedMessage(key, data, mesType)
	signedData, _ := proto.Marshal(newSignedMessage)
	toSend := CreatePrefixedMessage(signedData)
	return toSend
}

func SliceContains(array interface{}, elem interface{}) bool {
	v := reflect.ValueOf(array)
	for i := 0; i < v.Len(); i++ {
		if v.Index(i).Interface() == elem {
			return true
		}
	}
	return false
}

func CreateErrorMessage(error string) []byte {
	return CreatePrefixedMessage([]byte("ERR:" + error))
}
