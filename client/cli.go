// +build !heroku

package main

import (
	"net"
	"fmt"
	"code.google.com/p/goprotobuf/proto"
	"airdispat.ch/airdispatch"
	"airdispat.ch/common"
	"flag"
	"crypto/ecdsa"
	"encoding/hex"
)

// -----------------------
// Configuration Variables
// -----------------------

// Program Changing Variables
var interactivity *bool = flag.Bool("i", false, "specify this flag to make the program interactive")
var mode *string = flag.String("mode", "", "specify the mode on which to operate the program")

// Specific Constants
var acting_address *string = flag.String("address", "", "specify the address you would like to look up")
var remote_mailserver *string = flag.String("remote", "localhost:2048", "specify the remote mailserver on which to connect")
var tracking_server *string = flag.String("tracker", "localhost:2048", "specify the tracking server on which to query")
var mail_location *string = flag.String("location", "", "specify a location for messages for a specific address to be delivered to")


// Key Variables
var myAddress string
var key *ecdsa.PrivateKey

// Mode Constants
const REGISTRATION = "registration"
const QUERY = "query"
const ALERT = "alert"
const SEND = "send"
const CHECK = "check"
const KEYGEN = "keygen"

func main() {
	// Parse the Command Line Flags
	flag.Parse()

	// If we expect to be interactive, prompt the user for the configuration variables.
	if *interactivity {
		fmt.Print("Mode: ")
		fmt.Scanln(mode)
		fmt.Print("Tracking Server: ")
		fmt.Scanln(tracking_server)

		// Specify the Remote Mailserver if you are Sending an Alert
		if *mode != REGISTRATION && *mode != QUERY {
			fmt.Print("Remote Mailserver: ")
			fmt.Scanln(remote_mailserver)
		}

		// Specify the Location to Send Messages to if you are Sending a registration
		if *mode == REGISTRATION {
			fmt.Print("Location to Send Messages to: ")
			fmt.Scanln(mail_location)
		}

		fmt.Print("Send or Query Address: ")
		fmt.Scanln(acting_address)
	}
	
	// Determine what to do based on the mode of the Client
	switch {
		case *mode == REGISTRATION:
			fmt.Println("Sending a Registration Request")
			sendRegistration(*tracking_server, *mail_location)
		case *mode == QUERY:
			if *acting_address == "" {
				fmt.Println("You must supply an address to lookup from the tracker.")
				return
			}
			fmt.Println("Sending a Query for " + *acting_address)
			sendQuery(*tracking_server, *acting_address)
		case *mode == ALERT:
			if *acting_address == "" {
				fmt.Println("You must supply an address to send the alert to.")
				return
			}
			fmt.Println("Sending a Mail Alert for " + *acting_address)
			sendAlert(*tracking_server, *acting_address, *remote_mailserver)
		case *mode == SEND:
			sendMail(*acting_address, *remote_mailserver)
		default:
			fmt.Println("You must specify a mode to run this in. -mode registration or -mode query or specify -i for interactive mode")
	}
}

func connectToServer(remote string) net.Conn {
	address, _ := net.ResolveTCPAddr("tcp", remote)

	// Connect to the Remote Mail Server
	conn, err := net.DialTCP("tcp", nil, address)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Cannot connect to server.")
		return nil
	}
	return conn
}

func keygen() {
	key, _ = common.CreateKey()
	createdAddress := common.StringAddress(&key.PublicKey)
	myAddress = createdAddress
	fmt.Println("Created the Address:", createdAddress)
}

func sendRegistration(tracker string, location string) {
	// Connect to the Tracking Server
	tracker_conn := connectToServer(tracker)
	defer tracker_conn.Close()

	// Generate a signing keypair
	keygen()

	// Specify the Message Type and get the Byte Key
	mesType := common.REGISTRATION_MESSAGE
	byteKey := common.KeyToBytes(&key.PublicKey)
	
	// Create the Registration Message
	newRegistration := &airdispatch.AddressRegistration{
		Address: &myAddress,
		PublicKey: byteKey,
		Location: &location, 
	}

	// Create the Signed Message
	regData, _ := proto.Marshal(newRegistration)
	toSend := common.CreateAirdispatchMessage(regData, key, mesType)

	// Send the Message
	tracker_conn.Write(toSend)
}

func sendQuery(tracker string, address string) string {
	// Connect to the Tracking Server
	tracker_conn := connectToServer(tracker)
	defer tracker_conn.Close()

	// Generate a Signing Keypair
	keygen()

	// Create the new Query Message
	newQuery := &airdispatch.AddressRequest {
		Address: &myAddress,
	}

	// Setup the new Message
	mesType := common.QUERY_MESSAGE
	queryData, _ := proto.Marshal(newQuery)
	totalBytes := common.CreateAirdispatchMessage(queryData, key, mesType)

	// Send the Message
	tracker_conn.Write(totalBytes)

	// Get the Response
	data, _ := common.ReadAirdispatchMessage(tracker_conn)
	
	// Format the Response
	newQueryResponse := &airdispatch.AddressResponse{}
	proto.Unmarshal(data, newQueryResponse)
	
	// Alert the User to the Found Address
	fmt.Println("Received Location for Address: ", *newQueryResponse.ServerLocation)
	return *newQueryResponse.ServerLocation
}

func sendMail(address string, mailserver string) {
	// Generate a signing keypair
	keygen()

	mail_conn := connectToServer(mailserver)
	defer mail_conn.Close()

	fmt.Println("Time to define the data!")

	// TODO: Add some encryption types
	// Define the Encoding as None (for now)
	var enc = "none"

	// Make Shell for Mail to Send
	mail := &airdispatch.Mail { FromAddress: &myAddress, Encryption: &enc }
	mailData := &airdispatch.MailData{}

	// Create an Array of Mail Data Types for us to append to
	allTypes := make([]*airdispatch.MailData_DataType, 0) 

	// TODO: Find a way to do this non-interactively (if at all possible)
	// Loop Forever
	for {
		// Define variables to read into
		var typename string
		var data string

		fmt.Print("Data Type (or done to stop): ")
		fmt.Scanln(&typename)
		// Quit if we must stop
		if typename == "done" { break }

		fmt.Print("Data: ")
		fmt.Scanln(&data)

		// Fill out the Data Type Structure
		newData := &airdispatch.MailData_DataType {
			TypeName: &typename,
			Payload: []byte(data),
		}

		// Append the New type to the Type Array
		allTypes = append(allTypes, newData)
	}

	// Load the array into the Mail
	mailData.Payload = allTypes
	theMail, _ := proto.Marshal(mailData)

	// TODO: Encrypt theMail (if necessary)
	mail.Data = theMail

	// TODO: Allow sending to Multiple Recipients
	// Load the Send Request with the MailMessage
	sendRequest := &airdispatch.SendMailRequest {
		ToAddress: []string{address},
		StoredMessage: mail,
	}
	
	// Convert the Structure into Bytes
	sendBytes, _ := proto.Marshal(sendRequest)
	mesType := common.SEND_REQUEST
	toSend := common.CreateAirdispatchMessage(sendBytes, key, mesType)

	// Send the Message
	mail_conn.Write(toSend)
} 

func sendAlert(tracker string, address string, mailserver string) {
	// Generate a Signing Keypair
	keygen()

	// Find the recipientServer for the address, and connect to it
	recipientServer := sendQuery(tracker, address)
	recipient_conn := connectToServer(recipientServer)

	// Allow the User to Specify a Specific Hash
	toHash := "hello"
	if *interactivity {
		fmt.Println("Specifiy a message to generate an ID for: ")
		fmt.Scanln(&toHash)
	}

	// Create the Message Id
	hash := hex.EncodeToString(common.HashSHA(nil, []byte(toHash)))

	// Fill Out the alert Structure
	newAlert := &airdispatch.Alert {
		ToAddress: &address,
		Location: &mailserver,
		MessageId: &hash,
	}

	// Create the Message
	alertData, _ := proto.Marshal(newAlert)
	toSend := common.CreateAirdispatchMessage(alertData, key, common.ALERT_MESSAGE)

	// Send the Alert
	recipient_conn.Write(toSend)
}
