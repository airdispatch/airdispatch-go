package main

import (
	"airdispat.ch/server/framework"
	"flag"
	"strings"
	"time"
	"airdispat.ch/common"
	"airdispat.ch/airdispatch"
	"crypto/ecdsa"
	"encoding/hex"
	"os"
	"fmt"
)

// Configuration Varables
var port = flag.String("port", "2048", "select the port on which to run the mail server")
var trackers = flag.String("trackers", "", "prepopulate the list of trackers that this server will query by using a comma seperated list of values")
var me = flag.String("me", getHostname(), "the location of the server that it should broadcast to the world")
var key_file = flag.String("key", "", "the file to store keys")

func getHostname() string {
	s, _ := os.Hostname()
	return s
}

type PostOffice map[string]Mailbox
type Mailbox map[string] Mail
type Mail struct {
	From string
	Location string
	approved []string
	data []byte
	receivedTime time.Time
}

// Set up the Mailboxes of Users (to store incoming mail)
var mailboxes PostOffice

// Set up the outgoing public notes
var notices PostOffice

// Set up the outgoing messages boxes
var storedMessages Mailbox

// Variables that store information about the server
var connectedTrackers []string
var serverLocation string
var serverKey *ecdsa.PrivateKey

func main() {
	// Parse the configuration Command Line Falgs
	flag.Parse()

	// Initialize Incoming and Outgoing Mailboxes
	mailboxes = make(PostOffice)
	notices = make(PostOffice)
	storedMessages = make(Mailbox)

	// Populate the Trackers List
	connectedTrackers = strings.Split(*trackers, ",")
	if (*trackers == "") { connectedTrackers = make([]string, 0) }

	// Create a Signing Key for the Server
	loadedKey, err := common.LoadKeyFromFile(*key_file)

	if err != nil {

		loadedKey, err = common.CreateADKey()
		if err != nil {
			fmt.Println("Unable to Create Tracker Key")
			return
		}

		if *key_file != "" {

			err = loadedKey.SaveKeyToFile(*key_file)
			if err != nil {
				fmt.Println("Unable to Save Tracker Key")
				return
			}
		}

	}
	fmt.Println("Loaded Address", loadedKey.HexEncode())

	// Find the location of this server
	serverLocation = *me
	handler := &myServer{}
	theServer := framework.Server{
		LocationName: *me,
		Key: loadedKey,
		TrackerList: connectedTrackers,
		Delegate: handler,
	}
	serverErr := theServer.StartServer(*port)
	if serverErr != nil {
		fmt.Println("Unable to Start Server")
		fmt.Println(err)
	}

}

type myServer struct{
	framework.BasicServer
}

// Function that Handles an Alert of a Message
func (myServer) SaveIncomingAlert(alert *airdispatch.Alert, alertData []byte, fromAddr string) {
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

func (myServer) SavePublicMail(theMail []byte, fromAddr string) {
	// Populate the Record to Store the Data
	storedData := Mail {
		data: theMail,
		receivedTime: time.Now(),
	}

	// Get the notice box of the From Address
	_, ok := notices[fromAddr]
	if !ok {
		notices[fromAddr] = make(Mailbox)
	}

	// Store the Public Message in the Box
	notices[fromAddr][GetMessageId(theMail)] = storedData
}

func (myServer) SavePrivateMail(theMail []byte, toAddress []string) (id string) {
	// Get a hash of the Message
	hash := GetMessageId(theMail)

	// Create a Record to Store the Message in the Outgoing Mail Box
	storedData := Mail {
		approved: toAddress,
		data: theMail,
		receivedTime: time.Now(),
	}

	// Store the Message in the Database
	storedMessages[hash] = storedData

	return hash
}

func GetMessageId(theMail []byte) string {
	return hex.EncodeToString(common.HashSHA(theMail, nil))
}

func (myServer) RetrieveMessageForUser(id string, addr string) ([]byte) {
	// TODO: Allow this type of DATA to retrieve multiple messages... Maybe?
	// Get the Outgoing Message with that ID
	message, _ := storedMessages[id]

	// Check that the Sending Address is one of the Approved Recipients
	if !common.SliceContains(message.approved, addr) {
		return nil
	}

	return message.data
}

func (m myServer) RetrieveInbox(addr string, since uint64) [][]byte {
	return m.retrieveData(addr, since, mailboxes)
}

func (m myServer) RetrievePublic(fromAddr string, since uint64) [][]byte {
	return m.retrieveData(fromAddr, since, notices)
}

func (myServer) retrieveData(fromAddr string, since uint64, theBox PostOffice) [][]byte {
	// Get the `TimeSince` field
	timeSince := time.Unix(int64(since), 0)

	// Get the public notices box for that address
	boxes, ok := theBox[fromAddr]
	if !ok {
		// If it does not exist, alert the user
		// conn.Write(common.CreateErrorMessage("no public messages for that id"))
		return nil
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
	return output
}
