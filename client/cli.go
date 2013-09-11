// +build !heroku

package main

import (
	"airdispat.ch/client/framework"
	"airdispat.ch/common"
	"bufio"
	"flag"
	"fmt"
	"os"
	"time"
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
var tracking_server *string = flag.String("tracker", "localhost:1024", "specify the tracking server on which to query")
var mail_location *string = flag.String("location", "", "specify a location for messages for a specific address to be delivered to")
var key_location *string = flag.String("key", "", "specify a file to save or load the keys")
var id *string = flag.String("message_id", "profile", "the id of the message you want to download")

// Mode Constants
const REGISTRATION = "registration"
const QUERY = "query"
const SEND = "send"
const CHECK = "check"
const PUBLIC = "pub_check"
const KEYGEN = "keygen"
const DOWNLOAD = "download"

var credentials *framework.Client

func main() {
	// Parse the Command Line Flags
	flag.Parse()

	credentials = &framework.Client{}

	// If we expect to be interactive, prompt the user for the configuration variables.
	if *interactivity {
		fmt.Print("Mode: ")
		fmt.Scanln(mode)
	}

	// Go ahead and verify the mode.
	if *mode != REGISTRATION && *mode != QUERY && *mode != SEND && *mode != CHECK && *mode != PUBLIC && *mode != KEYGEN && *mode != DOWNLOAD {
		fmt.Println("You must specify a mode to run the program in, or specify interactive mode.")
		fmt.Println("Currently supported modes: ", REGISTRATION, QUERY, SEND, KEYGEN, CHECK, PUBLIC)
		os.Exit(1)
	}

	if *interactivity {

		// Nothing else needed if its a KEYGEN Query
		if *mode == KEYGEN {
			fmt.Print("File to Save Keys to: ")
			fmt.Scanln(key_location)

			key, _ := common.CreateADKey()
			key.SaveKeyToFile(*key_location)

			return
		}

		if *mode != SEND && *mode != CHECK && *mode != DOWNLOAD {
			fmt.Print("Tracking Server: ")
			fmt.Scanln(tracking_server)
		}

		// Specify the Remote Mailserver if you are Sending an Alert
		if *mode != QUERY && *mode != PUBLIC {
			fmt.Print("Remote Mailserver: ")
			fmt.Scanln(remote_mailserver)
		}

		if *mode != CHECK && *mode != REGISTRATION && *mode != DOWNLOAD {
			// Otherwise, specify the address that you are querying or sending to.
			fmt.Print("Send or Query Address: ")
			fmt.Scanln(acting_address)
		}

		if *mode == DOWNLOAD {
			fmt.Print("ID of Message to Download: ")
			fmt.Scanln(id)
		}

		fmt.Print("File to Load Keys From: ")
		fmt.Scanln(key_location)
	}

	theKey, err := common.LoadKeyFromFile(*key_location)
	if err != nil {
		fmt.Println("Unable to Load Keys From File")
		fmt.Println(err)
		return
	}
	credentials.Populate(theKey)
	fmt.Println(credentials.Key.HexEncode())

	credentials.MailServer = *remote_mailserver
	theTrackerList := common.CreateADTrackerList(common.CreateADTracker(*tracking_server))

	// Determine what to do based on the mode of the Client
	switch {
	// REGISTRATION Message
	case *mode == REGISTRATION:
		fmt.Println("Sending a Registration Request")
		credentials.SendRegistration(*tracking_server)

	// QUERY MESSAGE
	case *mode == QUERY:
		fmt.Println("Sending a Query for " + *acting_address)
		theAddress := common.CreateADAddress(*acting_address)
		location, err := theAddress.GetLocation(credentials.Key, theTrackerList)
		if err != nil {
			fmt.Println("Unable to Lookup Location")
			fmt.Println(err)
			return
		}

		fmt.Println("Found Location", location)

		encryptionKey, err := theAddress.GetEncryptionKey(credentials.Key, theTrackerList)
		if err != nil {
			fmt.Println("Unable to Get Encryption Key")
			fmt.Println(err)
			return
		}

		fmt.Println("And Public Encryption Key", encryptionKey)

	// SEND MESSAGE
	case *mode == SEND:
		sendMail(common.CreateADAddress(*acting_address), theTrackerList)

	// CHECK MESSAGE
	case *mode == CHECK:
		inbox, err := credentials.DownloadInbox(uint64(0))
		if err != nil {
			fmt.Println("Unable to Download Inbox")
			fmt.Println(err)
			return
		}

		for _, v := range inbox {
			// Print the Message
			v.DecryptPayload(credentials.Key)
			fmt.Println(v.PrintMessage())
		}

	// CHECK FOR PUBLIC MESSAGES
	case *mode == PUBLIC:
		theAddress := common.CreateADAddress(*acting_address)
		allMail, err := credentials.DownloadPublicMail(theTrackerList, theAddress, 0)
		if err != nil {
			fmt.Println("Unable to Download Public Mail")
			fmt.Println(err)
			return
		}

		for _, v := range allMail {
			v.DecryptPayload(credentials.Key)
			fmt.Println(v.PrintMessage())
		}

	case *mode == DOWNLOAD:
		theMail, err := credentials.DownloadSpecificMessageFromServer(*id, *remote_mailserver)
		if err != nil {
			fmt.Println("Unable to Download Public Mail")
			fmt.Println(err)
			return
		}

		theMail.DecryptPayload(credentials.Key)
		fmt.Println(theMail.PrintMessage())

	}
}

func sendMail(address *common.ADAddress, trackers *common.ADTrackerList) {
	fmt.Println("Time to define the data!")

	// Create an Array of Mail Data Types for us to append to
	allTypes := make([]*common.ADComponent, 0)

	// TODO: Find a way to do this non-interactively (if at all possible)
	// Loop Forever
	for {
		stdin := bufio.NewReader(os.Stdin)
		// Define variables to read into
		var typeName string
		var data string

		fmt.Print("Data Type (or done to stop): ")
		typeName, _ = ReadLine(stdin)
		// Quit if we must stop
		if typeName == "done" {
			break
		}

		fmt.Print("Data: ")
		data, _ = ReadLine(stdin)

		// Fill out the Data Type Structure
		newData := common.CreateADComponent(typeName, []byte(data))

		// Append the New type to the Type Array
		allTypes = append(allTypes, newData)
	}

	// Load the array into the Mail

	mail := common.CreateADMail(credentials.Key.ToAddress(), address, uint64(time.Now().Unix()), allTypes, common.ADEncryptionNone)

	// TODO: Encrypt theMail (if necessary)
	if address != nil {
		mail.EncryptionType = common.ADEncryptionRSA
	}

	credentials.SendMail(address, mail, trackers)
}

// Taken from http://stackoverflow.com/questions/6141604/go-readline-string

func ReadLine(r *bufio.Reader) (string, error) {
	var (
		isPrefix bool  = true
		err      error = nil
		line, ln []byte
	)
	for isPrefix && err == nil {
		line, isPrefix, err = r.ReadLine()
		ln = append(ln, line...)
	}
	return string(ln), err
}
