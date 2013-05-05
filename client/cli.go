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
	"crypto/elliptic"
	"encoding/hex"
	"encoding/gob"
	"math/big"
	"os"
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
var key_location *string = flag.String("key", "", "specify a file to save or load the keys")


// Mode Constants
const REGISTRATION = "registration"
const QUERY = "query"
const ALERT = "alert"
const SEND = "send"
const CHECK = "check"
const KEYGEN = "keygen"

// Keygen Variables
type EncodedKey struct {
	D, X, Y *big.Int
}

type CLIKey struct {
	Address string
	key *ecdsa.PrivateKey
	SaveKey EncodedKey 
}

var credentials CLIKey

func main() {
	// Parse the Command Line Flags
	flag.Parse()
	
	// Register the Elliptic Curve Parameters as Acceptable to Read/Write to File
	gob.Register(elliptic.CurveParams{})

	// If we expect to be interactive, prompt the user for the configuration variables.
	if *interactivity {
		fmt.Print("Mode: ")
		fmt.Scanln(mode)
		
		// Nothing else needed if its a KEYGEN Query
		if *mode != KEYGEN {
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
			} else {
				// Otherwise, specify the address that you are querying or sending to.
				fmt.Print("Send or Query Address: ")
				fmt.Scanln(acting_address)
			}

			fmt.Print("File to Load Keys From: ")
		} else {
			fmt.Print("File to Save Keys to: ")
		}
		fmt.Scanln(key_location)
	}
	
	// Determine what to do based on the mode of the Client
	switch {
		// REGISTRATION Message
		case *mode == REGISTRATION:
			fmt.Println("Sending a Registration Request")
			loadKeys(*key_location)
			sendRegistration(*tracking_server, *mail_location)

		// QUERY MESSAGE	
		case *mode == QUERY:
			fmt.Println("Sending a Query for " + *acting_address)
			loadKeys(*key_location)
			sendQuery(*tracking_server, *acting_address)

		// ALERT MESSAGE
		case *mode == ALERT:
			fmt.Println("Sending a Mail Alert for " + *acting_address)
			loadKeys(*key_location)
			sendAlert(*tracking_server, *acting_address, *remote_mailserver)

		// SEND MESSAGE
		case *mode == SEND:
			loadKeys(*key_location)
			sendMail(*acting_address, *remote_mailserver)

		// GENERATE KEYS
		case *mode == KEYGEN:
			saveKeys(*key_location)

		// Otherwise, throw an error.
		default:
			fmt.Println("You must specify a mode to run the program in, or specify interactive mode.")
			fmt.Println("Currently supported modes: ", REGISTRATION, QUERY, ALERT, SEND, KEYGEN)
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

func createKey() {
	key, _ := common.CreateKey()
	createdAddress := common.StringAddress(&key.PublicKey)

	saveKey := EncodedKey{key.D, key.PublicKey.X, key.PublicKey.Y}
	credentials = CLIKey{createdAddress, key, saveKey}
	fmt.Println("Created the Address:", createdAddress)
}

func loadKeys(filename string) {
	// Open the File for Loading
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Unable to Open File")
		fmt.Println(err)
		return
	}

	// Create the decoder
	dec := gob.NewDecoder(file)
	// Load from the File
	err = dec.Decode(&credentials)
	if err != nil {
		fmt.Println("Unable to get the credentials from the file.")
		fmt.Println(err)
	}

	// Reconstruct the Key
	newPublicKey := ecdsa.PublicKey{common.EllipticCurve, credentials.SaveKey.X, credentials.SaveKey.Y}
	newPrivateKey := ecdsa.PrivateKey{newPublicKey, credentials.SaveKey.D}
	credentials.key = &newPrivateKey
}

func saveKeys(filename string) {
	// First, create the keys that we will use
	createKey()

	// Create the File to Store the Keys in
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("Unable to Create File")
		fmt.Println(err)
		return
	}

	// Create the Encoder
	enc := gob.NewEncoder(file)

	// Write to File
	err = enc.Encode(credentials)
	if err != nil {
		fmt.Println("Unable to Write Credentials")
		fmt.Println(err)
	}
}

func sendRegistration(tracker string, location string) {
	// Connect to the Tracking Server
	tracker_conn := connectToServer(tracker)
	defer tracker_conn.Close()

	mesType := common.REGISTRATION_MESSAGE
	byteKey := common.KeyToBytes(&credentials.key.PublicKey)
	
	// Create the Registration Message
	newRegistration := &airdispatch.AddressRegistration{
		Address: &credentials.Address,
		PublicKey: byteKey,
		Location: &location, 
	}

	// Create the Signed Message
	regData, _ := proto.Marshal(newRegistration)
	toSend := common.CreateAirdispatchMessage(regData, credentials.key, mesType)

	// Send the Message
	tracker_conn.Write(toSend)
}

func sendQuery(tracker string, address string) string {
	// Connect to the Tracking Server
	tracker_conn := connectToServer(tracker)
	defer tracker_conn.Close()

	newQuery := &airdispatch.AddressRequest {
		Address: &credentials.Address,
	}

	// Setup the new Message
	mesType := common.QUERY_MESSAGE
	queryData, _ := proto.Marshal(newQuery)
	totalBytes := common.CreateAirdispatchMessage(queryData, credentials.key, mesType)

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
	// Connect to the Remote Mailserver
	mail_conn := connectToServer(mailserver)
	defer mail_conn.Close()

	fmt.Println("Time to define the data!")

	// TODO: Add some encryption types
	// Define the Encoding as None (for now)
	var enc = "none"

	// Make Shell for Mail to Send
	mail := &airdispatch.Mail { FromAddress: &credentials.Address, Encryption: &enc }
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
	toSend := common.CreateAirdispatchMessage(sendBytes, credentials.key, mesType)

	// Send the Message
	mail_conn.Write(toSend)
} 

func sendAlert(tracker string, address string, mailserver string) {
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
	toSend := common.CreateAirdispatchMessage(alertData, credentials.key, common.ALERT_MESSAGE)

	// Send the Alert
	recipient_conn.Write(toSend)
}
