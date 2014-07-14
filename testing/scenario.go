package testing

import (
	"airdispat.ch/identity"
	"airdispat.ch/routing"
	"fmt"
)

type Scenario struct {
	Sender   *identity.Identity
	Receiver *identity.Identity
	Server   *identity.Identity
	Router   routing.Router
}

func CreateScenario() (scene Scenario, err error) {
	sender, err := identity.CreateIdentity()
	if err != nil {
		return
	}
	sender.SetLocation("localhost:9090")

	receiver, err := identity.CreateIdentity()
	if err != nil {
		return
	}
	receiver.SetLocation("localhost:9091")

	server, err := identity.CreateIdentity()
	if err != nil {
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

	return
}
