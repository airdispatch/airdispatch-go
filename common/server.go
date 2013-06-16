package common;

import (
	"net"
	"airdispat.ch/airdispatch"
	"code.google.com/p/goprotobuf/proto"
	"crypto/ecdsa"
	"strings"
	"errors"
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
func LookupLocation(toAddr string, trackerList []string, key *ecdsa.PrivateKey) (string, error) {
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

func SendQuery(tracker string, addr string, key *ecdsa.PrivateKey) (string, error) {
	address, _ := net.ResolveTCPAddr("tcp", tracker)

	// Connect to Tracker
	conn, err := net.DialTCP("tcp", nil, address)

	if err != nil {
		return "", err
	}

	// Close the connection
	defer conn.Close()

	// Send a Query to the Tracker
	return SendQueryToConnection(conn, addr, key)
}

// A function that will send a query message over a connection
func SendQueryToConnection(conn net.Conn, addr string, key *ecdsa.PrivateKey) (string, error) {
	// Create a new Query Message
	newQuery := &airdispatch.AddressRequest {
		Address: &addr,
	}

	// Set the Message Type and get the Bytes of the Message
	mesType := QUERY_MESSAGE
	queryData, err := proto.Marshal(newQuery)
	if err != nil {
		return "", err
	}

	// Create the Message to be sent over the wire
	totalBytes := CreateAirdispatchMessage(queryData, key, mesType)

	// Send the message and wait for a response
	conn.Write(totalBytes)
	data, err := ReadAirdispatchMessage(conn)
	if err != nil {
		return "", err
	}

	// Unmarshal the Response
	newQueryResponse := &airdispatch.AddressResponse{}
	proto.Unmarshal(data, newQueryResponse)

	// Return the Location
	return *newQueryResponse.ServerLocation, nil
}

type AirdispatchAddressType int
var AirdispatchAddressNormal AirdispatchAddressType = 1
var AirdispatchAddressLegacy AirdispatchAddressType = 2
var AirdispatchAddressDirect AirdispatchAddressType = 3

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