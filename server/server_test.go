package server

import (
	"airdispat.ch/identity"
	"airdispat.ch/message"
	"errors"
	"testing"
	"time"
)

// Test 1: Sending Message
var passed bool

func TestSendMessage(t *testing.T) {
	passed = false

	sender, err := identity.CreateIdentity()
	if err != nil {
		t.Error(err)
	}
	sender.SetLocation("localhost:9090")

	receiver, err := identity.CreateIdentity()
	if err != nil {
		t.Error(err)
	}
	receiver.SetLocation("localhost:9091")

	server, err := identity.CreateIdentity()
	if err != nil {
		t.Error(err)
	}
	server.SetLocation("localhost:9090")

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
	}

	time.Sleep(1 * time.Second)

	if !passed {
		t.Error("Unable to receive Message Description.")
	}
}

type TestSendMessageDelegate struct {
	BasicServer
	t     *testing.T
	Users []*identity.Identity
}

func (t TestSendMessageDelegate) HandleError(err *ServerError) {
	t.t.Error(err)
}
func (t TestSendMessageDelegate) SaveMessageDescription(m *MessageDescription) {
	passed = true

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
	return nil
}
func (t TestSendMessageDelegate) RetrieveMessageListForUser(since uint64, author *identity.Address, forAddr *identity.Address) (messages *MessageList) {
	return nil
}

func TestTransferMessage(t *testing.T) {

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
