package common

import (
	"crypto/rsa"
	"fmt"
)

type ADAddress struct {
	address       string
	location      string
	encryptionKey *rsa.PublicKey
}

func CreateADAddress(address string) *ADAddress {
	return &ADAddress{}
}

func (a *ADAddress) GetAddress() string {
	return a.address
}
