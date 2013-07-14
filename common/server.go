package common;

import (
	"net"
	"airdispat.ch/airdispatch"
	"code.google.com/p/goprotobuf/proto"
	"strings"
	"errors"
	"reflect"
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

// A function that will get the Location of an Address
func LookupLocation(toAddr string, trackerList []string, key *ADKey) (string, error) {
	switch GetAddressType(toAddr) {
		case AirdispatchAddressNormal:
			// Loop Over Every Connected Tracker
			for _, value := range(trackerList) {
				location, err := SendQuery(value, toAddr, key)
				if err == nil {
					return location, nil
				}
			}
		case AirdispatchAddressLegacy:
			addressParts := strings.Split(toAddr, "@")
			return SendQuery(addressParts[1], addressParts[0], key)
		case AirdispatchAddressDirect:
			addressParts := strings.Split(toAddr, "@@")
			return addressParts[1], nil
		default:
			// If we cannot determine the address type, return nothing
			return "", errors.New("Could Not Determine the Type of Airdispatch Address")
	}

	// If we could not lookup the address, return nothing
	return "", errors.New("Could Not Locate Address In Provided Trackers")
}

func SendQuery(tracker string, addr string, key *ADKey) (string, error) {
	conn, err := ConnectToServer(tracker)
	if err != nil {
		return "", err
	}

	// Close the connection
	defer conn.Close()

	// Send a Query to the Tracker
	return SendQueryToConnection(conn, tracker, addr, key)
}

// A function that will send a query message over a connection
func SendQueryToConnection(conn net.Conn, trackerLocation string, addr string, key *ADKey) (string, error) {
	// Create a new Query Message
	newQuery := &airdispatch.AddressRequest {
		Address: &addr,
	}

	// Set the Message Type and get the Bytes of the Message
	queryData, err := proto.Marshal(newQuery)
	if err != nil {
		return "", err
	}

	// Create the Message to be sent over the wire
	newMessage := &ADMessage {
		Payload: queryData,
		MessageType: QUERY_MESSAGE,
	}

	totalBytes, err := key.CreateADMessage(newMessage)
	if err != nil {
		return "", err
	}

	// Send the message and wait for a response
	conn.Write(totalBytes)
	_, readMessage, err := ReadADMessage(conn)
	if err != nil {
		return "", err
	}

	expectedAddress, err := VerifyTrackerAddress(trackerLocation)
	if err == nil {
		if expectedAddress != readMessage.FromAddress {
			return "", errors.New("Tracker DNS did not have the correct Address")
		}
	}

	if readMessage.MessageType != QUERY_RESPONSE_MESSAGE {
		return "", errors.New("Tracker Did Not Return Correct Message Type")
	}

	// Unmarshal the Response
	newQueryResponse := &airdispatch.AddressResponse{}
	proto.Unmarshal(readMessage.Payload, newQueryResponse)

	// Return the Location
	return *newQueryResponse.ServerLocation, nil
}

func VerifyTrackerAddress(tracker string) (string, error) {
	records, err := net.LookupTXT(tracker)
	if err != nil {
		return "", errors.New("Couldn't fetch TXT Records")
	}

	for _, v := range(records) {
		if strings.HasPrefix(v, "adtp__cert:") {
			return strings.TrimPrefix(v, "adtp__cert:"), nil
		}
	}

	return "", errors.New("Couldn't Find Certificate")
}

func GetAddressType(addr string) AirdispatchAddressType {
	switch strings.Count(addr, "@") {
		case 0:
			return AirdispatchAddressNormal
		case 1:
			return AirdispatchAddressLegacy
		case 2:
			return AirdispatchAddressDirect
	}
	return -1
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