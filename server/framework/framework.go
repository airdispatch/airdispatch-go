package framework

import (
	"fmt"
	"net"
	"airdispat.ch/common"
	"airdispat.ch/airdispatch"
	"code.google.com/p/goprotobuf/proto"
	"crypto/ecdsa"
	"bytes"
)

type ServerError struct {
	Location string
	Error string
}

type serverHandler interface {
	HandleError(err ServerError)

	SavePublicMail(mailData []byte, fromAddress string)
	SavePrivateMail(mailData []byte, toAddresses []string) (messageId string)

	SaveIncomingAlert(alert *airdispatch.Alert, alertData []byte, fromAddr string)

	AllowConnection(fromAddr string) bool

	RetrieveMessage(id string) (message []byte, approvedRecipients []string)
	RetrievePublic(fromAddr string, since uint64) (messages [][]byte)
	RetrieveInbox(addr string, since uint64) (messages [][]byte)
}

type Server struct {
	Port string
	LocationName string
	TrackerList []string
	Key *ecdsa.PrivateKey
	ServerHandler serverHandler
}

var thisServer *Server

func StartServer(theServer *Server) *Server {
	thisServer = theServer
	// Resolve the Address of the Server
	service := ":" + thisServer.Port
	tcpAddr, _ := net.ResolveTCPAddr("tcp4", service)
	fmt.Println("Starting Airdispatch Server On ", service)

	// Start the Server
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Unable to Listen for Requests")
		return nil
	}
	fmt.Println("Server is running...")

	serverLoop(listener)

	return thisServer
}

func serverLoop(listener *net.TCPListener) {
	// Loop forever, waiting for connections
	for {
		// Accept a Connection
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
			fmt.Println("Unable to Connect to Client", conn.RemoteAddr())
		}

		// Concurrently handle the connection
		go handleClient(conn)
	}	
}

func handleClient(conn net.Conn) {
	// Close the Connection after Handling
	defer conn.Close()

	// Read in the Message
	payload, messageType, theAddress, err := common.ReadSignedMessage(conn)
	if err != nil {
		fmt.Println("Error reading the message.")
		fmt.Println(err)
		return
	}

	if !thisServer.ServerHandler.AllowConnection(theAddress) {
		return
	}

	// Switch based on the Message Type
	switch messageType {

		case common.ALERT_MESSAGE:
			fmt.Println("Received Alert")

			// Unmarshal the stored message
			assigned := &airdispatch.Alert{}
			err := proto.Unmarshal(payload, assigned)
			if (err != nil) { fmt.Println("Bad Payload."); return; }

			// Handle the Alert
			handleAlert(assigned, payload, theAddress)

		case common.RETRIEVAL_MESSAGE:
			fmt.Println("Received Retrival Request")

			// Unmarshal the stored message
			assigned := &airdispatch.RetrieveData{}
			err := proto.Unmarshal(payload, assigned)
			if (err != nil) { fmt.Println("Bad Payload."); return; }

			// Handle the Retrieval Message
			handleRetrieval(assigned, theAddress, conn)

		case common.SEND_REQUEST:
			fmt.Println("Received Request to Send Message")

			// Unmarshal the stored message
			assigned := &airdispatch.SendMailRequest{}
			err := proto.Unmarshal(payload, assigned)
			if (err != nil) { fmt.Println("Bad Payload."); return; }

			// Handle the Send Request
			handleSendRequest(assigned, theAddress)
	}
}

// Function that Handles an Alert of a Message
func handleAlert(alert *airdispatch.Alert, alertData []byte, fromAddr string) {
	thisServer.ServerHandler.SaveIncomingAlert(alert, alertData, fromAddr)
}

// Function that Handles a DataRetrieval Message
func handleRetrieval(retrieval *airdispatch.RetrieveData, toAddr string, conn net.Conn) {
	// Get the Type of the Message and Switch on it
	c := retrieval.RetrievalType
	switch {

		// Receieved a Normal Retrieval Message (Lookup the Message ID)
		case bytes.Equal(c, common.RETRIEVAL_TYPE_NORMAL()):
			message, approved := thisServer.ServerHandler.RetrieveMessage(*retrieval.MessageId)
			if message == nil {
				// If there is no message stored with that ID, then send back an error
				conn.Write(common.CreateErrorMessage("no message for that id"))
				return
			}

			// Check that the Sending Address is one of the Approved Recipients
			if !common.SliceContains(approved, toAddr) {
				conn.Write(common.CreateErrorMessage("not an approved recipient"))
				return
			}

			// If it passes these checks, send the message back through the connection
			conn.Write(common.CreatePrefixedMessage(message))

		// Received a Public Retrieval Message (Return all Messages Since the Date Provided)
		case bytes.Equal(c, common.RETRIEVAL_TYPE_PUBLIC()):

			output := thisServer.ServerHandler.RetrievePublic(*retrieval.FromAddress, *retrieval.SinceDate)

			// Alert the Client that an Array is Coming
			arrayData := common.CreateArrayedMessage(uint32(len(output)), thisServer.Key)
			conn.Write(arrayData)

			// Write all of the Data
			for _, v := range(output) {
				conn.Write(common.CreatePrefixedMessage(v))
			}

		// Received a Mine Retrieval Message (Return all Messages that are Stored - Since the Date Provided)	
		case bytes.Equal(c, common.RETRIEVAL_TYPE_MINE()):
			output := thisServer.ServerHandler.RetrieveInbox(toAddr, *retrieval.SinceDate)

			arrayData := common.CreateArrayedMessage(uint32(len(output)), thisServer.Key)
			conn.Write(arrayData)

			// Write all of the Data
			for _, v := range(output) {
				conn.Write(common.CreatePrefixedMessage(v))
			}

		default:
			fmt.Println("Unable to Respond to Message")
	}
}

// Function that Handles a Request to Send a Message
func handleSendRequest(request *airdispatch.SendMailRequest, fromAddr string) {
	// Check to see if it a public message or not
	if len(request.ToAddress) != 0 && request.ToAddress[0] != fromAddr && request.ToAddress[0] != "" {
		hash := thisServer.ServerHandler.SavePrivateMail(request.StoredMessage, request.ToAddress)

		for _, v := range(request.ToAddress) {
			// For every address that the Message is to be sent to, lookup its location and send it an alert
			loc := common.LookupLocation(v, thisServer.TrackerList, thisServer.Key)
			SendAlert(loc, hash, v)
		}
	} else {
		thisServer.ServerHandler.SavePublicMail(request.StoredMessage, fromAddr)
	}
}

// A function that delivers an alert to a location
func SendAlert(location string, message_id string, toAddr string) {
	address, _ := net.ResolveTCPAddr("tcp", location)

	// Connect to the remote server
	conn, err := net.DialTCP("tcp", nil, address)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Unable to connect to the receiving server.")
		return
	}

	// Populate the Alert message
	newAlert := &airdispatch.Alert {
		ToAddress: &toAddr,
		Location: &thisServer.LocationName,
		MessageId: &message_id,
	}
	alertData, _ := proto.Marshal(newAlert)

	// Create the Message to Send
	bytesToSend := common.CreateAirdispatchMessage(alertData, thisServer.Key, common.ALERT_MESSAGE)

	// Write the Message
	conn.Write(bytesToSend)
	conn.Close()
}