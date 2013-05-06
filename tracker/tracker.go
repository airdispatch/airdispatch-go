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

	// Initialize the Database of Addresses
	storedAddresses = make(map[string]RegisteredAddress)

	// Get the Address of the Server
	service := ":" + *port
	tcpAddr, _ := net.ResolveTCPAddr("tcp4", service)

	// Start the Server Listener
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Unable to Listen for Requests")
		return
	}
	fmt.Println("Listening on", service)

	// Loop Forever while we wait for Clients
	for {
		// Open a Connection to the Client
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
			fmt.Println("Unable to Connect to Client", conn.RemoteAddr())
		}

		// Concurrently Handle the Connection
		go handleClient(conn)

	}

}

func handleClient(conn net.Conn) {
	// Read in the Message Sent from the Client
	totalBytes, err := common.ReadAirdispatchMessage(conn)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Error reading in the message.")
		return
	}

	// Unmarshal the Message into the Message Type
	downloadedMessage := &airdispatch.SignedMessage{}
	err = proto.Unmarshal(totalBytes[0:], downloadedMessage)
	if err != nil {
		fmt.Println(err)
		fmt.Println("The message is malformed!")
		return
	}

	// Verify the Signed Message is Correct (Check for Spoofing)
	if !common.VerifySignedMessage(downloadedMessage) {
		fmt.Println("Message is not signed properly. Discarding")
		return
	}

	// Get the Message Type
	messageType := downloadedMessage.MessageType
	// Get the Sending Address
	theAddress := common.StringAddress(common.BytesToKey(downloadedMessage.SigningKey))

	// Determine how to Proceed based on the Message Type
	switch *messageType {

		// Handle Registration
		case common.REGISTRATION_MESSAGE:
			fmt.Println("Received Registration")

			// Unmarshal the Sent Data
			assigned := &airdispatch.AddressRegistration{}
			err := proto.Unmarshal(downloadedMessage.Payload, assigned)
			if (err != nil) { fmt.Println("Bad Payload."); return; }

			handleRegistration(theAddress, assigned) 

		// Handle Query
		case common.QUERY_MESSAGE:
			fmt.Println("Received Query")

			// Unmarshall the Sent Data
			assigned := &airdispatch.AddressRequest{}
			err := proto.Unmarshal(downloadedMessage.Payload, assigned)
			if (err != nil) { fmt.Println("Bad Payload."); return; }

			handleQuery(theAddress, assigned, conn)
	}
}

func handleRegistration(theAddress string, reg *airdispatch.AddressRegistration) {
	// Check to see if a Username was provided
	username := ""
	if reg.Username != nil {
		username = *reg.Username
	}

	// Load the RegisteredAddress with the sent information
	data := RegisteredAddress{
		public_key: reg.PublicKey,
		location: *reg.Location,
		username: username,
	}

	// Store the RegisterdAddress in the Database
	storedAddresses[theAddress] = data
}

func handleQuery(theAddress string, req *airdispatch.AddressRequest, conn net.Conn) {
	fmt.Println("Querying for", *req.Address)

	// Lookup the Address in the Database
	info, ok := storedAddresses[*req.Address]
	if !ok {
		// Return an Error Message if it Does not Exist
		data := common.CreateErrorMessage("not located here")
		conn.Write(data)
		return
	}

	// Create a Formatted Message
	response := &airdispatch.AddressResponse {
		ServerLocation: &info.location,
		Address: &theAddress,
		PublicKey: info.public_key,
	}
	data, _ := proto.Marshal(response)

	// Send the Response
	conn.Write(common.CreatePrefixedMessage(data))
}
