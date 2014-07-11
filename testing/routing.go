package testing

import (
	"airdispat.ch/identity"
	"errors"
)

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
