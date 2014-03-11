package server

import (
	"airdispat.ch/identity"
	"airdispat.ch/message"
	"airdispat.ch/wire"
	"errors"
	"fmt"
	"testing"
	"time"
)

// Test 1: Sending Message
var gotSaveDescription bool

func TestSendMessage(t *testing.T) {
	fmt.Println("--- Starting Send Message Test")
	gotSaveDescription = false

	sender, err := identity.CreateIdentity()
	if err != nil {
		t.Error(err)
		return
	}
	sender.SetLocation("localhost:9090")

	receiver, err := identity.CreateIdentity()
	if err != nil {
		t.Error(err)
		return
	}
	receiver.SetLocation("localhost:9091")

	server, err := identity.CreateIdentity()
	if err != nil {
		t.Error(err)
		return
	}
	server.SetLocation("localhost:9092")

	testRouter := &StaticRouter{
		Keys: []*identity.Identity{sender, receiver},
	}

	testDelegate := &TestSendMessageDelegate{
		t:     t,
		Users: []*identity.Identity{receiver},
	}

	theServer := Server{
		LocationName: "localhost:9091",
		Key:          server,
		Delegate:     testDelegate,
		Router:       testRouter,
	}
	go func() {
		theServer.StartServer("9091")
	}()

	time.Sleep(1 * time.Second)
	t.Log("Sending Test Description")

	msgDescription := CreateMessageDescription("testMessage", "localhost:9090", sender.Address, receiver.Address)
	err = message.SignAndSend(msgDescription, sender, receiver.Address)
	if err != nil {
		t.Error(err)
		return
	}

	time.Sleep(1 * time.Second)

	if !gotSaveDescription {
		t.Error("Unable to receive Message Description.")
	}

}

type TestSendMessageDelegate struct {
	BasicServer
	t     *testing.T
	Users []*identity.Identity
}

func (t TestSendMessageDelegate) HandleError(err *ServerError) {
	fmt.Println(err.Error, err.Location)
	t.t.Error(err)
	panic(err)
}
func (t TestSendMessageDelegate) SaveMessageDescription(m *MessageDescription) {
	gotSaveDescription = true

	t.t.Log("Received Message Description")
	if m.Name != "testMessage" {
		t.t.Error("Name was incorrect in Message Description")
	}
	if m.Location != "localhost:9090" {
		t.t.Error("Location was incorrect in Message Description")
	}
}
func (t TestSendMessageDelegate) IdentityForUser(addr *identity.Address) *identity.Identity {
	for _, x := range t.Users {
		if x.Address.String() == addr.String() {
			return x
		}
	}
	return nil
}
func (t TestSendMessageDelegate) RetrieveMessageForUser(id string, author *identity.Address, forAddr *identity.Address) (message *message.Mail) {
	t.t.Error("Wrong function.")
	return nil

}
func (t TestSendMessageDelegate) RetrieveMessageListForUser(since uint64, author *identity.Address, forAddr *identity.Address) (messages *MessageList) {
	t.t.Error("Wrong function.")
	return nil
}

// Test 2: Tranferring a Message
var receivedTranfer bool

func TestTransferMessage(t *testing.T) {
	fmt.Println("--- Starting Transfer Message Test")

	receivedTranfer = false

	sender, err := identity.CreateIdentity()
	if err != nil {
		t.Error(err)
		return
	}
	sender.SetLocation("localhost:9090")

	receiver, err := identity.CreateIdentity()
	if err != nil {
		t.Error(err)
		return
	}
	receiver.SetLocation("localhost:9093")

	server, err := identity.CreateIdentity()
	if err != nil {
		t.Error(err)
		return
	}
	server.SetLocation("localhost:9092")

	fmt.Println("Sender", sender.Address.String())
	fmt.Println("Receiver", receiver.Address.String())
	fmt.Println("Server", server.Address.String())

	testRouter := &StaticRouter{
		Keys: []*identity.Identity{sender, receiver},
	}

	testDelegate := &TestTransferMessageDelegate{
		t:     t,
		Users: []*identity.Identity{receiver},
	}

	theServer := Server{
		LocationName: "localhost:9093",
		Key:          server,
		Delegate:     testDelegate,
		Router:       testRouter,
	}
	go func() {
		theServer.StartServer("9093")
	}()

	time.Sleep(1 * time.Second)
	t.Log("Sending Test Description")

	msgDescription := CreateTransferMessage("testMessage", sender.Address, receiver.Address)

	signed, err := message.SignMessage(msgDescription, sender)
	if err != nil {
		t.Error(err)
		return
	}

	enc, err := signed.EncryptWithKey(receiver.Address)
	if err != nil {
		t.Error(err)
		return
	}

	conn, err := message.ConnectToServer(receiver.Address.Location)
	if err != nil {
		t.Error(err)
		return
	}
	defer conn.Close()

	err = enc.SendMessageToConnection(conn)
	if err != nil {
		t.Error(err)
		return
	}

	time.Sleep(1 * time.Second)

	msg, err := message.ReadMessageFromConnection(conn)
	if err != nil {
		t.Error(err)
		return
	}

	receivedSign, err := msg.Decrypt(sender)
	if err != nil {
		t.Error(err)
		return
	}

	if !receivedSign.Verify() {
		t.Error("Couldn't verify message.")
		return
	}

	_, messageType, _, err := receivedSign.ReconstructMessage()
	if err != nil {
		t.Error(err)
		return
	}
	if messageType != wire.MailCode {
		t.Error("Wrong Message type got", messageType)
		return
	}

	time.Sleep(5 * time.Second)

	if !receivedTranfer {
		t.Error("Unable to receive Message Description.")
		return
	}
	fmt.Println("--- Finishing Transfer Message Test")
}

type TestTransferMessageDelegate struct {
	BasicServer
	t     *testing.T
	Users []*identity.Identity
}

func (t TestTransferMessageDelegate) HandleError(err *ServerError) {
	fmt.Println(err.Error, err.Location)
	t.t.Error(err)
	panic(err)
}
func (t TestTransferMessageDelegate) SaveMessageDescription(m *MessageDescription) {
	t.t.Error("Wrong function.")
	panic(nil)
}
func (t TestTransferMessageDelegate) IdentityForUser(addr *identity.Address) *identity.Identity {
	for _, x := range t.Users {
		if x.Address.String() == addr.String() {
			return x
		}
	}
	return nil
}
func (t TestTransferMessageDelegate) RetrieveMessageForUser(id string, author *identity.Address, forAddr *identity.Address) *message.Mail {
	t.t.Log("Successfully recevied transfer message.")
	if id != "testMessage" {
		t.t.Error("Cannot retrieve message that isn't tested.")
	}
	mail := message.CreateMail(author, forAddr)
	mail.Components = []message.Component{
		message.Component{"test", []byte("hello world")},
	}
	receivedTranfer = true
	return mail
}
func (t TestTransferMessageDelegate) RetrieveMessageListForUser(since uint64, author *identity.Address, forAddr *identity.Address) (messages *MessageList) {
	t.t.Error("Wrong function.")
	return nil
}

func TestPublicMessage(t *testing.T) {

}

// Define a blank router that we can use for testing purposes.
type StaticRouter struct {
	Keys []*identity.Identity
}

func (t *StaticRouter) Lookup(addr string) (*identity.Address, error) {
	for _, x := range t.Keys {
		if x.Address.String() == addr {
			return x.Address, nil
		}
	}
	return nil, errors.New("Unable to find address.")
}

func (t *StaticRouter) Register(*identity.Identity) error {
	return nil
}

func (t *StaticRouter) LookupAlias(alias string) (*identity.Address, error) {
	return nil, nil
}
