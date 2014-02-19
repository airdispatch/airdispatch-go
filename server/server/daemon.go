package main

import (
	"airdispat.ch/server"
	"crypto/ecdsa"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
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
type Mailbox map[string]Mail
type Mail struct {
	approved     []string
	mail         *common.ADMail // Each Mail Structure will either store a Mail Object (if it is outgoing) or an Alert Object (if it is incoming)
	alert        *common.ADAlert
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
	if *trackers == "" {
		connectedTrackers = make([]string, 0)
	}

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
		Key:          loadedKey,
		TrackerList:  common.CreateADTrackerListWithStrings(connectedTrackers...),
		Delegate:     handler,
	}
	serverErr := theServer.StartServer(*port)
	if serverErr != nil {
		fmt.Println("Unable to Start Server")
		fmt.Println(err)
	}

}

type myServer struct {
	framework.BasicServer
}

// Function that Handles an Alert of a Message
// INCOMING
func (myServer) SaveIncomingAlert(alert *common.ADAlert) {
	// Get the recipient address of the message
	toAddr := alert.ToAddress

	// Form a ReceivedMessage Record for the database
	theMessage := Mail{
		alert:        alert,
		receivedTime: time.Now(),
	}

	// Attempt to Get the Mailbox of the User
	_, ok := mailboxes[toAddr.ToString()]
	if !ok {
		// TODO: Catch if the user is registered with the server or not
		// If it cannot, make a mailbox
		mailboxes[toAddr.ToString()] = make(Mailbox)
	}

	// Store the Record in the User's Mailbox
	mailboxes[toAddr.ToString()][alert.MessageID] = theMessage
}

// OUTGOING
func (myServer) SavePublicMail(theMail *common.ADMail) {
	// Populate the Record to Store the Data
	storedData := Mail{
		mail:         theMail,
		receivedTime: time.Now(),
	}

	// Get the notice box of the From Address
	_, ok := notices[theMail.FromAddress.ToString()]
	if !ok {
		notices[theMail.FromAddress.ToString()] = make(Mailbox)
	}

	// Store the Public Message in the Box
	notices[theMail.FromAddress.ToString()][GetMessageId(theMail)] = storedData
}

// OUTGOING
func (myServer) SavePrivateMail(theMail *common.ADMail, approved []string) (id string) {
	// Get a hash of the Message
	hash := GetMessageId(theMail)

	// Create a Record to Store the Message in the Outgoing Mail Box
	storedData := Mail{
		approved:     approved,
		mail:         theMail,
		receivedTime: time.Now(),
	}

	// Store the Message in the Database
	storedMessages[hash] = storedData

	return hash
}

func GetMessageId(theMail *common.ADMail) string {
	// RETURN TO LOOK AT THIS.
	return hex.EncodeToString(theMail.HashContents())
}

func (myServer) RetrieveMessageForUser(id string, addr *common.ADAddress) *common.ADMail {
	// TODO: Allow this type of DATA to retrieve multiple messages... Maybe?
	// Get the Outgoing Message with that ID
	message, _ := storedMessages[id]

	// Check that the Sending Address is one of the Approved Recipients
	if !common.SliceContains(message.approved, addr.ToString()) {
		fmt.Println("Couldn't authenticate user.")
		return nil
	}

	return message.mail
}

func (m myServer) RetrieveInbox(addr *common.ADAddress, since uint64) []*common.ADAlert {
	// Get the `TimeSince` field
	timeSince := time.Unix(int64(since), 0)

	// Get the public notices box for that address
	boxes, ok := mailboxes[addr.ToString()]
	if !ok {
		// If it does not exist, return nothing
		return nil
	}

	// Make an array of messages to tack onto
	output := make([]*common.ADAlert, 0)

	// Loop through the messages
	for _, v := range boxes {
		// Append the notice to the output if it was sent after the 'TimeSince'
		if v.receivedTime.After(timeSince) {
			output = append(output, v.alert)
		}
	}
	return output
}

func (m myServer) RetrievePublic(fromAddr *common.ADAddress, since uint64) []*common.ADMail {
	// Get the `TimeSince` field
	timeSince := time.Unix(int64(since), 0)

	// Get the public notices box for that address
	boxes, ok := notices[fromAddr.ToString()]
	if !ok {
		// If it does not exist, return nothing
		return nil
	}

	// Make an array of messages to tack onto
	output := make([]*common.ADMail, 0)

	// Loop through the messages
	for _, v := range boxes {
		// Append the notice to the output if it was sent after the 'TimeSince'
		if v.receivedTime.After(timeSince) {
			output = append(output, v.mail)
		}
	}
	return output
}
