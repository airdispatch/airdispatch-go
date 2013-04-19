package main

import (
	"net"
	"fmt"
	"code.google.com/p/goprotobuf/proto"
	"airdispat.ch/airdispatch"
	"airdispat.ch/common"
	"flag"
)

var mode = flag.String("mode", "", "select the mode of the tracker connection, 'query' or 'register'")
var lookup = flag.String("address", "", "specify the address you would like to look up")

const REGISTRATION = "registration"
const QUERY = "query"

func main() {
	flag.Parse()
	address, _ := net.ResolveTCPAddr("tcp", "localhost:2048")

	conn, err := net.DialTCP("tcp", nil, address)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Cannot connect to server.")
		return
	}

	switch {
		case *mode == REGISTRATION:
			fmt.Println("Sending a Registration Request")
			sendRegistration(conn)
		case *mode == QUERY:
			if *lookup == "" {
				fmt.Println("You must supply an address for a lookup query.")
				return
			}
			fmt.Println("Sending a Query for " + *lookup)
			sendQuery(conn, *lookup)
		case true:
			fmt.Println("You must specify a mode to run this in. -mode registration or -mode query")
	}
	conn.Close()
}

func sendRegistration(conn net.Conn) {
	key, _ := common.CreateKey()
	createdAddress := common.StringAddress(&key.PublicKey)
	fmt.Println("Created the Address:", createdAddress)
	mesType := "reg"
	byteKey := common.KeyToBytes(&key.PublicKey)
	location := "google.com"
	
	newRegistration := &airdispatch.AddressRegistration{
		Address: &createdAddress,
		PublicKey: byteKey,
		Location: &location, 
	}

	regData, _ := proto.Marshal(newRegistration)
	newSignedMessage, _ := common.CreateSignedMessage(key, regData, mesType)
	data, _ := proto.Marshal(newSignedMessage)
	toSend := common.CreatePrefixedMessage(data)
	conn.Write(toSend)
}

func sendQuery(conn net.Conn, addr string) {
	defer conn.Close()

	key, _ := common.CreateKey()

	newQuery := &airdispatch.AddressRequest {
		Address: &addr,
	}

	mesType := "que"
	queryData, _ := proto.Marshal(newQuery)
	newSignedMessage, _ := common.CreateSignedMessage(key, queryData, mesType)
	signedData, _ := proto.Marshal(newSignedMessage)
	totalBytes := common.CreatePrefixedMessage(signedData)

	conn.Write(totalBytes)
	data, _ := common.ReadAirdispatchMessage(conn)
	
	newQueryResponse := &airdispatch.AddressResponse{}
	proto.Unmarshal(data, newQueryResponse)
	
	fmt.Println("Received Location for Address:", *newQueryResponse.ServerLocation)
} 
