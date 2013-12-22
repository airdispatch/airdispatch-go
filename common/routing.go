package common

type ADRouter interface {
	QueryForAddress(address *ADAddress, key *ADKey) (*ADQueryResponse, error)
	RegisterAddress(key *ADKey, mailserver string) error
}
