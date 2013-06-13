package common;

import (
	"net"
	"fmt"
	"airdispat.ch/airdispatch"
	"code.google.com/p/goprotobuf/proto"
	"crypto/ecdsa"
)

// A function that will get the Location of an Address
func LookupLocation(toAddr string, trackerList []string, key *ecdsa.PrivateKey) string {
	// Loop Over Every Connected Tracker
	for _, v := range(trackerList) {
		address, _ := net.ResolveTCPAddr("tcp", v)

		// Connect to Tracker
		conn, err := net.DialTCP("tcp", nil, address)
		if err != nil {
			fmt.Println(err)
			fmt.Println("Unable to connect to the tracking server.")
			continue
		}

		// Send a Query to the Tracker
		finalLocation, err := SendQuery(conn, toAddr, key)
		// Return the Address if there were no errors
		if err == nil {
			return finalLocation
		}

		// Close the connection
		conn.Close()
	}
	// If we have not returned a location yet, we cannot return anything
	return ""
}

// A function that will send a query message over a connection
func SendQuery(conn net.Conn, addr string, key *ecdsa.PrivateKey) (string, error) {
	// Create a new Query Message
	newQuery := &airdispatch.AddressRequest {
		Address: &addr,
	}

	// Set the Message Type and get the Bytes of the Message
	mesType := QUERY_MESSAGE
	queryData, _ := proto.Marshal(newQuery)

	// Create the Message to be sent over the wire
	totalBytes := CreateAirdispatchMessage(queryData, key, mesType)

	// Send the message and wait for a response
	conn.Write(totalBytes)
	data, _ := ReadAirdispatchMessage(conn)

	// Unmarshal the Response
	newQueryResponse := &airdispatch.AddressResponse{}
	proto.Unmarshal(data, newQueryResponse)

	// Return the Location
	return *newQueryResponse.ServerLocation, nil
}