package main

import (
	"airdispat.ch/identity"
	"airdispat.ch/message"
	"airdispat.ch/server"
	"flag"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"
)

// Configuration Varables
var port = flag.String("port", "2048", "select the port on which to run the mail server")

var me = flag.String("me", getServerLocation(), "the location of the server that it should broadcast to the world")
var key_file = flag.String("key", "", "the file to store keys")

func getServerLocation() string {
	s, _ := os.Hostname()
	ips, _ := net.LookupHost(s)
	return ips[0] + ":" + *port
}

// Postoffice Stores Many User's Mailboxes
type PostOffice map[string]*Mailbox

func (p PostOffice) StoreOutgoingMessageForUser(user string, m *message.EncryptedMessage) ServerMail {
	box, ok := p[user]
	if !ok {
		box = &Mailbox{
			Incoming: make([]*message.EncryptedMessage, 0),
			Outgoing: make(map[string]ServerMail),
		}
	}

	s := ServerMail{
		Mail:     m,
		Name:     strconv.Itoa(rand.Int()),
		SentTime: time.Now(),
	}
	box.Outgoing[s.Name] = s
	p[user] = box
	return s
}

type Mailbox struct {
	Incoming []*message.EncryptedMessage
	Outgoing map[string]ServerMail
	Public   []ServerMail
	Identity *identity.Identity
}

type ServerMail struct {
	Mail     *message.EncryptedMessage
	Name     string
	SentTime time.Time
}

// Set up the Mailboxes of Users (to store incoming mail)
var mailboxes PostOffice

// Set up the outgoing messages boxes
var storedMessages Mailbox

// Variables that store information about the server
var connectedTrackers []string
var serverLocation string
var serverKey *identity.Identity

func main() {
	rand.Seed(time.Now().Unix())
	// Parse the configuration Command Line Falgs
	flag.Parse()

	// Initialize Incoming and Outgoing Mailboxes
	mailboxes = make(PostOffice)

	// Create a Signing Key for the Server
	handler := &myServer{}
	loadedKey, err := identity.LoadKeyFromFile(*key_file)
	if err != nil {

		loadedKey, err = identity.CreateIdentity()
		if err != nil {
			handler.HandleError(&server.ServerError{"Creating Mailserver Key", err})
			return
		}

		if *key_file != "" {
			err = loadedKey.SaveKeyToFile(*key_file)
			if err != nil {
				handler.HandleError(&server.ServerError{"Saving Mailserver Key", err})
				return
			}
		}

	}
	serverKey = loadedKey
	handler.LogMessage("Loaded Address", loadedKey.Address.String())

	// Find the location of this server
	serverLocation = *me
	theServer := server.Server{
		LocationName: *me,
		Key:          serverKey,
		Delegate:     handler,
	}

	StartServer(theServer, handler)
}

func StartServer(theServer server.Server, handler *myServer) {
	err := theServer.StartServer(*port)
	if err != nil {
		handler.HandleError(&server.ServerError{"Saving Mailserver Key", err})
	}
	os.Exit(1)
}

type myServer struct {
	server.BasicServer
}

// Function that Handles an Alert of a Message
// INCOMING
func (myServer) SaveMessageDescription(desc *message.EncryptedMessage) {
	// Get the recipient address of the message
	toAddr := desc.To

	// Attempt to Get the Mailbox of the User
	v, ok := mailboxes[toAddr.String()]
	if !ok {
		// TODO: Catch if the user is registered with the server or not
		// If it cannot, make a mailbox
		v = &Mailbox{
			Incoming: make([]*message.EncryptedMessage, 0),
			Outgoing: make(map[string]ServerMail),
		}
	}

	// Store the Record in the User's Mailbox
	v.Incoming = append(v.Incoming, desc)
	mailboxes[toAddr.String()] = v
}

func (myServer) RetrieveMessageForUser(name string, author *identity.Address, forAddr *identity.Address) *message.EncryptedMessage {
	box, ok := mailboxes[author.String()]
	if !ok {
		return nil
	}

	mail, ok := box.Outgoing[name]
	if !ok {
		return nil
	}

	return mail.Mail
}

func (m myServer) RetrieveMessageListForUser(since uint64, author *identity.Address, forAddr *identity.Address) []*message.EncryptedMessage {
	// Get the `TimeSince` field
	timeSince := time.Unix(int64(since), 0)
	output := make([]*message.EncryptedMessage, 0)

	// Get the public notices box for that address
	box, ok := mailboxes[author.String()]
	if !ok {
		// If it does not exist, return nothing
		return nil
	}

	// Loop through the messages
	for _, v := range box.Public {
		// Append the notice to the output if it was sent after the 'TimeSince'
		if v.SentTime.After(timeSince) {
			output = append(output, v.Mail)
		}
	}
	return output
}
