package main

import (
	"fmt"
	"net"
	"flag"
	"os"
	"bytes"
	"strings"
	"time"
	"airdispat.ch/common"
	"airdispat.ch/airdispatch"
	"code.google.com/p/goprotobuf/proto"
	"crypto/ecdsa"
	"encoding/hex"
)

// Configuration Varables
var port = flag.String("port", "2048", "select the port on which to run the mail server")
var trackers = flag.String("trackers", "", "prepopulate the list of trackers that this server will query by using a comma seperated list of values")

// Set up the Mailboxes of Users (to store incoming mail)
var mailboxes map[string] Mailbox
type Mailbox map[string] Mail
type Mail struct {
	From string
	Location string
	data []byte
	receivedTime time.Time
}

// Set up the outgoing public notes
var notices map[string] []MailData

// Set up the outgoing messages boxes
var storedMessages map[string] MailData
type MailData struct {
	// An array of approved recipients
	approved []string

	// The actual mail message (We keep it marshalled for fast transmission
	data []byte

	// The time received
	receivedTime time.Time
}

// Variables that store information about the server
var connectedTrackers []string
var serverLocation string
var serverKey *ecdsa.PrivateKey

func main() {
	// Parse the configuration Command Line Falgs
	flag.Parse()

	// Initialize Incoming and Outgoing Mailboxes
	mailboxes = make(map[string]Mailbox)
	storedMessages = make(map[string]MailData)

	// Populate the Trackers List
	connectedTrackers = strings.Split(*trackers, ",")
	if (*trackers == "") { connectedTrackers = make([]string, 0) }

	// Create a Signing Key for the Server
	serverKey, _ = common.CreateKey()

	// Find the location of this server
	serverLocation, _ = os.Hostname()

	// Resolve the Address of the Server
	service := ":" + *port
	tcpAddr, _ := net.ResolveTCPAddr("tcp4", service)

	// Start the Server
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Unable to Listen for Requests")
		return
	}
	fmt.Println("Listening on", service)

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

	// Read in the Sent Message
	totalBytes, err := common.ReadAirdispatchMessage(conn)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Error reading in the message.")
		return
	}

	// Get the Signed Message
	downloadedMessage := &airdispatch.SignedMessage{}
	err = proto.Unmarshal(totalBytes[0:], downloadedMessage)
	if err != nil {
		fmt.Println(err)
		fmt.Println("The message is malformed!")
		return
	}

	// Verify that the address of the message is not spoofed
	if !common.VerifySignedMessage(downloadedMessage) {
		fmt.Println("Message is not signed properly. Discarding")
		return
	}

	// Determine the sending Address of the Message and the Message Type
	messageType := downloadedMessage.MessageType
	theAddress := common.StringAddress(common.BytesToKey(downloadedMessage.SigningKey))

	// Switch based on the Message Type
	switch *messageType {

		case common.ALERT_MESSAGE:
			fmt.Println("Received Alert")

			// Unmarshal the stored message
			assigned := &airdispatch.Alert{}
			err := proto.Unmarshal(downloadedMessage.Payload, assigned)
			if (err != nil) { fmt.Println("Bad Payload."); return; }

			// Handle the Alert
			handleAlert(assigned, downloadedMessage.Payload, theAddress)

		case common.RETRIEVAL_MESSAGE:
			fmt.Println("Received Retrival Request")

			// Unmarshal the stored message
			assigned := &airdispatch.RetrieveData{}
			err := proto.Unmarshal(downloadedMessage.Payload, assigned)
			if (err != nil) { fmt.Println("Bad Payload."); return; }

			// Handle the Retrieval Message
			handleRetrieval(assigned, theAddress, conn)

		case common.SEND_REQUEST:
			fmt.Println("Received Request to Send Message")

			// Unmarshal the stored message
			assigned := &airdispatch.SendMailRequest{}
			err := proto.Unmarshal(downloadedMessage.Payload, assigned)
			if (err != nil) { fmt.Println("Bad Payload."); return; }

			// Handle the Send Request
			handleSendRequest(assigned, theAddress)
	}
}

// Function that Handles an Alert of a Message
func handleAlert(alert *airdispatch.Alert, alertData []byte, fromAddr string) {
	// Get the recipient address of the message
	toAddr := *alert.ToAddress

	// Form a ReceivedMessage Record for the database
	theMessage := Mail{
		Location: *alert.Location,
		From: fromAddr,
		data: alertData,
		receivedTime: time.Now(),
	}

	// Attempt to Get the Mailbox of the User
	_, ok := mailboxes[toAddr]
	if !ok {
		// TODO: Catch if the user is registered with the server or not
		// If it cannot, make a mailbox
		mailboxes[toAddr] = make(Mailbox)
	}

	// Store the Record in the User's Mailbox
	mailboxes[toAddr][*alert.MessageId] = theMessage
}

// Function that Handles a DataRetrieval Message
func handleRetrieval(retrieval *airdispatch.RetrieveData, toAddr string, conn net.Conn) {
	// Get the Type of the Message and Switch on it
	c := retrieval.RetrievalType
	switch {

		// Receieved a Normal Retrieval Message (Lookup the Message ID)
		case bytes.Equal(c, common.RETRIEVAL_TYPE_NORMAL()):
			// TODO: Allow this type of DATA to retrieve multiple messages... Maybe?
			// Get the Outgoing Message with that ID
			message, ok := storedMessages[*retrieval.MessageId]
			if !ok {
				// If there is no message stored with that ID, then send back an error
				conn.Write(common.CreateErrorMessage("no message for that id"))
				return
			}

			// Check that the Sending Address is one of the Approved Recipients
			if !common.SliceContains(message.approved, toAddr) {
				conn.Write(common.CreateErrorMessage("not an approved recipient"))
				return
			}

			// If it passes these checks, send the message back through the connection
			conn.Write(common.CreatePrefixedMessage(message.data))

		// Received a Public Retrieval Message (Return all Messages Since the Date Provided)
		case bytes.Equal(c, common.RETRIEVAL_TYPE_PUBLIC()):
			// Get the `TimeSince` field
			timeSince := time.Unix(int64(*retrieval.SinceDate), 0)

			// Get the public notices box for that address
			boxes, ok := notices[*retrieval.FromAddress]
			if !ok {
				// If it does not exist, alert the user
				conn.Write(common.CreateErrorMessage("no public messages for that id"))
				return
			}

			// Make an array of messages to tack onto
			output := make([][]byte, 0)

			// Loop through the messages
			for _, v := range(boxes) {
				// Append the notice to the output if it was sent after the 'TimeSince'
				if (v.receivedTime.After(timeSince)) {
					output = append(output, v.data)
				}
			}

			// Alert the Client that an Array is Coming
			arrayData := common.CreateArrayedMessage(uint32(len(output)), serverKey)
			conn.Write(arrayData)

			// Write all of the Data
			for _, v := range(output) {
				conn.Write(common.CreatePrefixedMessage(v))
			}

		// Received a Mine Retrieval Message (Return all Messages that are Stored - Since the Date Provided)	
		case bytes.Equal(c, common.RETRIEVAL_TYPE_MINE()):
			// Get the `TimeSince` field
			timeSince := time.Unix(int64(*retrieval.SinceDate), 0)

			// Get the Users' Mailbox
			mailbox, ok := mailboxes[toAddr]
			if !ok {
				// If it does nto exist, alert the user that this isn't their mailserver
				conn.Write(common.CreateErrorMessage("user is not part of this server"))
				return
			}

			// Make an array of messages to tack onto
			output := make([][]byte, 0)

			// Loop through the messages
			for _, v := range(mailbox) {
				// Append the notice to the output if it was sent after the 'TimeSince'
				if (v.receivedTime.After(timeSince)) {
					output = append(output, v.data)
				}
			}

			arrayData := common.CreateArrayedMessage(uint32(len(output)), serverKey)
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
	if request.ToAddress != nil || request.ToAddress[0] == fromAddr {
		// Helper Variables so we don't have to access request everytime
		var toAddress []string = request.ToAddress
		var theMail = request.StoredMessage

		// Get a hash of the Message
		hash := hex.EncodeToString(common.HashSHA(theMail, nil))

		for _, v := range(toAddress) {
			// For every address that the Message is to be sent to, lookup its location and send it an alert
			loc := LookupLocation(v)
			SendAlert(loc, hash, v)
		}

		// Create a Record to Store the Message in the Outgoing Mail Box
		storeData := MailData {
			approved: toAddress,
			data: theMail,
			receivedTime: time.Now(),
		}

		// Store the Message in the Database
		storedMessages[hash] = storeData
	} else {
		var theMail = request.StoredMessage

		// Populate the Record to Store the Dat
		storedData := MailData {
			data: theMail,
			receivedTime: time.Now(),
		}

		// Get the notice box of the From Address
		boxes, ok := notices[fromAddr]
		if !ok {
			boxes = make([]MailData, 0)
		}

		// Store the Public Message in the Box
		notices[fromAddr] = append(boxes, storedData)
	}
}

// A function that will get the Location of an Address
func LookupLocation(toAddr string) string {
	// Loop Over Every Connected Tracker
	for _, v := range(connectedTrackers) {
		address, _ := net.ResolveTCPAddr("tcp", v)

		// Connect to Tracker
		conn, err := net.DialTCP("tcp", nil, address)
		if err != nil {
			fmt.Println(err)
			fmt.Println("Unable to connect to the tracking server.")
			continue
		}

		// Send a Query to the Tracker
		finalLocation, err := SendQuery(conn, toAddr)
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
func SendQuery(conn net.Conn, addr string) (string, error) {
	// Create a new Query Message
	newQuery := &airdispatch.AddressRequest {
		Address: &addr,
	}

	// Set the Message Type and get the Bytes of the Message
	mesType := common.QUERY_MESSAGE
	queryData, _ := proto.Marshal(newQuery)

	// Create the Message to be sent over the wire
	totalBytes := common.CreateAirdispatchMessage(queryData, serverKey, mesType)

	// Send the message and wait for a response
	conn.Write(totalBytes)
	data, _ := common.ReadAirdispatchMessage(conn)

	// Unmarshal the Response
	newQueryResponse := &airdispatch.AddressResponse{}
	proto.Unmarshal(data, newQueryResponse)

	// Return the Location
	return *newQueryResponse.ServerLocation, nil
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
		Location: &serverLocation,
		MessageId: &message_id,
	}
	alertData, _ := proto.Marshal(newAlert)

	// Create the Message to Send
	bytesToSend := common.CreateAirdispatchMessage(alertData, serverKey, common.ALERT_MESSAGE)

	// Write the Message
	conn.Write(bytesToSend)
	conn.Close()
}
