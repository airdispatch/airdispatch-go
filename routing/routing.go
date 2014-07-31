// Package routing provides abstractions for routers on the
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
	Register(id *identity.Identity, alias string, redirects map[string]*Redirect) error
	// Lookup function checks an address and returns an identity object.
	// Name is a type of lookup, either 'TX' for transfers, 'MAIL' for sending
	// mail 'ALE' for sending alerts, or '*' for default.
	Lookup(addr string, name LookupType) (*identity.Address, error)
	// Lookup function checks an alias and returns an identity object.
	LookupAlias(alias string, name LookupType) (*identity.Address, error)
}

// LookupType wraps a string that determines which redirects are followed in the
// routing layer.
type LookupType string

// Different constants for the lookup types.
const (
	LookupTypeTX      LookupType = "TX"
	LookupTypeMAIL    LookupType = "MAIL"
	LookupTypeALERT   LookupType = "ALE"
	LookupTypeDEFAULT LookupType = "*"
)

// Redirect is a type of record on a Registration that alerts the client to send
// messages of a certain type to a different location.
type Redirect struct {
	Type        LookupType
	Fingerprint string
	Alias       string
}
