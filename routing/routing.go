// The Routing package provides abstractions for routers on the
// AirDispatch network (translating addresses to server locations).
package routing

import (
	"airdispat.ch/identity"
)

// The Router provides a way for AirDispatch applications to
// translate aliases and address fingerprints to identity
// objects.
type Router interface {
	// Register function registers an identity with a router.
	Register(*identity.Identity) error
	// Lookup function checks an address and returns an identity object.
	Lookup(addr string) (*identity.Address, error)
	// Lookup function checks an alias and returns an identity object.
	LookupAlias(alias string) (*identity.Address, error)
}
