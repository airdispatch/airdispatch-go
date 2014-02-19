package routing

import "airdispat.ch/identity"

type Location string

func (l Location) Register(*identity.Identity) error {
	panic("Should not call Register on Location")
}

func (l Location) Lookup(addr string) (*identity.Address, error) {
	return &identity.Address{
		Location: string(l),
	}, nil
}

func (l Location) LookupAlias(alias string) (*identity.Address, error) {
	return &identity.Address{
		Location: string(l),
	}, nil
}
