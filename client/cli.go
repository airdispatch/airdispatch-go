// +build !heroku

package main

import (
	"fmt"
	"code.google.com/p/goprotobuf/proto"
	"airdispat.ch/client/framework"
	"airdispat.ch/airdispatch"
	"airdispat.ch/common"
	"flag"
	"os"
	"bufio"
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
const PUBLIC = "pub_check"
const KEYGEN = "keygen"

var credentials *framework.Client

func main() {
	// Parse the Command Line Flags
	flag.Parse()

	credentials = &framework.Client{}

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
			} else if *mode != CHECK {
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
	if *mode != KEYGEN {
		theKey, _ := common.LoadKeyFromFile(*key_location)
		credentials.Populate(theKey)
	}
	credentials.MailServer = *remote_mailserver

	// Determine what to do based on the mode of the Client
	switch {
		// REGISTRATION Message
		case *mode == REGISTRATION:
			fmt.Println("Sending a Registration Request")
			credentials.SendRegistration(*tracking_server, *mail_location)

		// QUERY MESSAGE	
		case *mode == QUERY:
			fmt.Println("Sending a Query for " + *acting_address)
			queriedLocation, _ := common.LookupLocation(*acting_address, []string{*tracking_server}, credentials.Key)
			fmt.Println("Found Location", queriedLocation)

		// SEND MESSAGE
		case *mode == SEND:
			sendMail(*acting_address)

		// CHECK MESSAGE
		case *mode == CHECK:
			inbox, _ := credentials.DownloadInbox(uint64(0))
			for _, v := range(inbox) {
				// Print the Message
				fmt.Println(common.PrintMessage(v))
			}

		// CHECK FOR PUBLIC MESSAGES
		case *mode == PUBLIC:
			allMail, _ := credentials.DownloadPublicMail([]string{*tracking_server}, *acting_address, 0)
			for _, v := range(allMail) {
				fmt.Println(common.PrintMessage(v))
			}

		// GENERATE KEYS
		case *mode == KEYGEN:
			key, _ := common.CreateKey()
			common.SaveKeyToFile(*key_location, key)

		// Otherwise, throw an error.
		default:
			fmt.Println("You must specify a mode to run the program in, or specify interactive mode.")
			fmt.Println("Currently supported modes: ", REGISTRATION, QUERY, SEND, KEYGEN, CHECK, PUBLIC)
	}
}

func sendMail(address string) {
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
		stdin := bufio.NewReader(os.Stdin)
		// Define variables to read into
		var typename string
		var data string

		fmt.Print("Data Type (or done to stop): ")
		typename, _ = ReadLine(stdin)
		// Quit if we must stop
		if typename == "done" { break }

		fmt.Print("Data: ")
		data, _ = ReadLine(stdin)

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

	// We need to marshal the mail message and pre-sign it, so the server can send it on our behalf
	marshalledMail, _ := proto.Marshal(mail)
	signedMessage, _ := common.CreateSignedMessage(credentials.Key, marshalledMail, common.MAIL_MESSAGE)
	toSave, _ := proto.Marshal(signedMessage)

	credentials.SendMail([]string{address}, toSave)
}

	// // Get the Unix Timestamp of the earliest message you want
	// since := uint64(0)
	// if (*interactivity) {
	// 	fmt.Print("Retrieve Messages Sent Since (Unix Timestamp): ")
	// 	fmt.Scanln(&since)
	// }

// Taken from http://stackoverflow.com/questions/6141604/go-readline-string

func ReadLine(r *bufio.Reader) (string, error) {
  var (isPrefix bool = true
       err error = nil
       line, ln []byte
      )
  for isPrefix && err == nil {
      line, isPrefix, err = r.ReadLine()
      ln = append(ln, line...)
  }
  return string(ln),err
}
