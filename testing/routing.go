package testing

import (
	"errors"

	"airdispat.ch/identity"
	"airdispat.ch/routing"
)

// Define a blank router that we can use for testing purposes.
type StaticRouter struct {
	Keys []*identity.Identity
}

func (t *StaticRouter) Lookup(addr string, typ routing.LookupType) (*identity.Address, error) {
	for _, x := range t.Keys {
		if x.Address.String() == addr {
			return x.Address, nil
		}
	}
	return nil, errors.New("Unable to find address.")
}

func (t *StaticRouter) Register(*identity.Identity, string, map[string]routing.Redirect) error {
	return nil
}

func (t *StaticRouter) LookupAlias(alias string, typ routing.LookupType) (*identity.Address, error) {
	return nil, nil
}
