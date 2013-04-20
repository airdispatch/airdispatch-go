package main

import (
	"net"
	"fmt"
	"code.google.com/p/goprotobuf/proto"
	"airdispat.ch/airdispatch"
	"airdispat.ch/common"
	"flag"
)

var port = flag.String("port", "2048", "select the port on which to run the tracking server")

var storedAddresses map[string]RegisteredAddress

type RegisteredAddress struct {
	public_key []byte
	location string
	username string
}

func main() {
	flag.Parse()

	storedAddresses = make(map[string]RegisteredAddress)

	service := ":" + *port
	tcpAddr, _ := net.ResolveTCPAddr("tcp4", service)

	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Unable to Listen for Requests")
		return
	}
	fmt.Println("Listening on", service)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
			fmt.Println("Unable to Connect to Client", conn.RemoteAddr())
		}

		go handleClient(conn)

	} 

}

func handleClient(conn net.Conn) {
	totalBytes, err := common.ReadAirdispatchMessage(conn)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Error reading in the message.")
		return
	}

	downloadedMessage := &airdispatch.SignedMessage{}
	err = proto.Unmarshal(totalBytes[0:], downloadedMessage)
	if err != nil {
		fmt.Println(err)
		fmt.Println("The message is malformed!")
		return
	}

	if !common.VerifySignedMessage(downloadedMessage) {
		fmt.Println("Message is not signed properly. Discarding")
		return
	}
	
	messageType := downloadedMessage.MessageType
	theAddress := common.StringAddress(common.BytesToKey(downloadedMessage.SigningKey))

	switch *messageType {
		case common.REGISTRATION_MESSAGE:
			fmt.Println("Received Registration")
			assigned := &airdispatch.AddressRegistration{}
			err := proto.Unmarshal(downloadedMessage.Payload, assigned)
			if (err != nil) { fmt.Println("Bad Payload."); return; }
			handleRegistration(theAddress, assigned) 
		case common.QUERY_MESSAGE:
			fmt.Println("Received Query")
			assigned := &airdispatch.AddressRequest{}
			err := proto.Unmarshal(downloadedMessage.Payload, assigned)
			if (err != nil) { fmt.Println("Bad Payload."); return; }
			handleQuery(theAddress, assigned, conn) 
	}
}

func handleRegistration(theAddress string, reg *airdispatch.AddressRegistration) {
	data := RegisteredAddress {
		public_key: reg.PublicKey,
		location: *reg.Location,
		username: "",
	}
	storedAddresses[theAddress] = data
}

func handleQuery(theAddress string, req *airdispatch.AddressRequest, conn net.Conn) {
	fmt.Println("Quering for", *req.Address)
	info, ok := storedAddresses[*req.Address]
	if !ok {
		data := common.CreateErrorMessage("not located here")
		conn.Write(data)
		return
	}
	response := &airdispatch.AddressResponse {
		ServerLocation: &info.location,
		PublicKey: info.public_key,
	}
	data, _ := proto.Marshal(response)
	conn.Write(common.CreatePrefixedMessage(data))
}
