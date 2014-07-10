package server

import (
	"airdispat.ch/identity"
	"airdispat.ch/message"
	"airdispat.ch/routing"
	"airdispat.ch/wire"
	"errors"
	"fmt"
	"testing"
	"time"
)

type Scenario struct {
	Sender   *identity.Identity
	Receiver *identity.Identity
	Server   *identity.Identity
	Router   routing.Router
}

func testingSetup(t *testing.T, delegate ServerDelegate) (started, quit chan bool, scene Scenario) {
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
	server.SetLocation("localhost:9091")

	fmt.Println("Sender", sender.Address.String())
	fmt.Println("Receiver", receiver.Address.String())
	fmt.Println("Server", server.Address.String())

	testRouter := &StaticRouter{
		Keys: []*identity.Identity{sender, receiver},
	}

	scene = Scenario{sender, receiver, server, testRouter}

	started = make(chan bool)
	quit = make(chan bool)

	theServer := Server{
		LocationName: "localhost:9091",
		Key:          server,
		Delegate:     delegate,
		Router:       testRouter,
		Start:        started,
		Quit:         quit,
	}

	go func() {
		theServer.StartServer("9091")
	}()

	return
}

// Test 1: Sending Message

func TestSendMessage(t *testing.T) {
	fmt.Println("--- Starting Send Message Test")

	errors := make(chan error, 1)
	testDelegate := &TestSendMessageDelegate{
		Errors: errors,
	}

	started, quit, scene := testingSetup(t, testDelegate)
	defer func() { quit <- true }()

	testDelegate.Decryption = scene.Receiver

	<-started

	msgDescription := CreateMessageDescription("testMessage", "localhost:9090", scene.Sender.Address, scene.Receiver.Address)
	err := message.SignAndSend(msgDescription, scene.Sender, scene.Receiver.Address)
	if err != nil {
		t.Error(err)
		return
	}

	if err = <-errors; err != nil {
		t.Error(err)
		return
	}
}

type TestSendMessageDelegate struct {
	BasicServer
	Errors     chan error
	Decryption *identity.Identity
}

func (t TestSendMessageDelegate) HandleError(err *ServerError) {
	t.Errors <- errors.New(fmt.Sprintf("%s at %s", err.Error, err.Location))
}

func (t TestSendMessageDelegate) SaveMessageDescription(m *message.EncryptedMessage) {
	message, err := m.Decrypt(t.Decryption)
	if err != nil {
		t.Errors <- err
		return
	}

	if !message.Verify() {
		t.Errors <- errors.New("Unable to verify message description.")
		return
	}

	data, typ, h, err := message.ReconstructMessage()
	if err != nil {
		t.Errors <- err
		return
	}

	if typ != wire.MessageDescriptionCode {
		t.Errors <- errors.New("Wrong type of message sent.")
		return
	}

	msg, err := CreateMessageDescriptionFromBytes(data, h)
	if err != nil {
		t.Errors <- err
		return
	}

	if msg.Name != "testMessage" {
		t.Errors <- errors.New("Name was incorrect in Message Description")
		return
	}
	if msg.Location != "localhost:9090" {
		t.Errors <- errors.New("Location was incorrect in Message Description")
		return
	}
	t.Errors <- nil
}

func (t TestSendMessageDelegate) RetrieveMessageForUser(id string, author *identity.Address, forAddr *identity.Address) (message *message.EncryptedMessage) {
	t.Errors <- errors.New("Wrong Function")
	return nil
}
func (t TestSendMessageDelegate) RetrieveMessageListForUser(since uint64, author *identity.Address, forAddr *identity.Address) (messages []*message.EncryptedMessage) {
	t.Errors <- errors.New("Wrong Function")
	return nil
}

// Test 2: Tranferring a Message

func TestTransferMessage(t *testing.T) {
	fmt.Println("--- Starting Transfer Message Test")

	errors := make(chan error, 1)
	testDelegate := &TestTransferMessageDelegate{
		Errors: errors,
	}

	started, quit, scene := testingSetup(t, testDelegate)
	defer func() { quit <- true }()

	testDelegate.Signer = scene.Receiver
	testDelegate.Router = scene.Router

	<-started

	msgDescription := CreateTransferMessage("testMessage", scene.Sender.Address, scene.Server.Address)

	_, typ, _, err := message.SendMessageAndReceive(msgDescription, scene.Sender, scene.Server.Address)

	// Check the Errors Channel Before Assuming Anything Else
	if err = <-errors; err != nil {
		t.Error(err)
		return
	}

	if err != nil {
		t.Error(err)
		return
	}
	if typ != wire.MailCode {
		t.Error("Wrong Message type got", typ)
		return
	}
}

type TestTransferMessageDelegate struct {
	BasicServer
	t      *testing.T
	Signer *identity.Identity
	Router routing.Router
	Errors chan error
}

func (t TestTransferMessageDelegate) HandleError(err *ServerError) {
	t.Errors <- errors.New(fmt.Sprintf("%s at %s", err.Error, err.Location))
}
func (t TestTransferMessageDelegate) SaveMessageDescription(m *message.EncryptedMessage) {
	t.Errors <- errors.New("Wrong Function - Save Message Description")
}
func (t TestTransferMessageDelegate) RetrieveMessageForUser(id string, author *identity.Address, forAddr *identity.Address) *message.EncryptedMessage {
	if id != "testMessage" {
		t.Errors <- errors.New("Cannot retrieve message that isn't tested.")
		return nil
	}

	mail := message.CreateMail(author, forAddr, time.Now())
	cmps := make(message.ComponentList)
	cmps.AddComponent(
		message.Component{
			Name: "test",
			Data: []byte("hello world"),
		},
	)
	mail.Components = cmps

	signed, err := message.SignMessage(mail, t.Signer)
	if err != nil {
		t.Errors <- err
		return nil
	}

	enc, err := signed.Encrypt(forAddr.String(), t.Router)
	if err != nil {
		t.Errors <- err
		return nil
	}

	t.Errors <- nil
	return enc
}
func (t TestTransferMessageDelegate) RetrieveMessageListForUser(since uint64, author *identity.Address, forAddr *identity.Address) (messages []*message.EncryptedMessage) {
	t.Errors <- errors.New("Wrong Function - Retrieve Message List")
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

func (t *StaticRouter) Register(*identity.Identity, string) error {
	return nil
}

func (t *StaticRouter) LookupAlias(alias string) (*identity.Address, error) {
	return nil, nil
}
