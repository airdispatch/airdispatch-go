package common

import (
	"airdispat.ch/airdispatch"
	"crypto/ecdsa"
	"crypto/rsa"
	"strings"
)

type ADAddress struct {
	address       string
	location      string
	username      string
	tracker       *ADTracker
	encryptionKey *rsa.PublicKey
	signingKey    *ecdsa.PublicKey
}

func CreateADAddress(address string) *ADAddress {
	output := &ADAddress{}

	switch strings.Count(address, "@") {
	case 2: //AirdispatchAddressDirect:
		addressParts := strings.Split(address, "@@")
		output.address = addressParts[0]
		output.location = addressParts[1]
	case 1: //AirdispatchAddressLegacy:
		addressParts := strings.Split(address, "@")
		output.username = addressParts[0]
		output.tracker = CreateADTracker(addressParts[1])
	case 0: //AirdispatchAddressNormal:
		output.address = address
	default:
		return nil
	}

	return output
}

func (a *ADAddress) GetLocation(k *ADKey, t *ADTrackerList) (string, error) {
	if a.location == "" {
		if a.address == "" {
			location, err := a.tracker.QueryForAddress(a, k)
			if err != nil {
				return "", err
			}

			a.location = location.Location
			a.encryptionKey = location.PublicKey
			a.address = location.EncodedAddress
		} else {
			location, err := t.Query(a, k)
			if err != nil {
				return "", err
			}

			a.location = location.Location
			a.encryptionKey = location.PublicKey
			a.address = location.EncodedAddress
		}
	}
	return a.location, nil
}

func (a *ADAddress) GetEncryptionKey(k *ADKey, t *ADTrackerList) (*rsa.PublicKey, error) {
	if a.encryptionKey == nil {
		_, err := a.GetLocation(k, t)
		if err != nil {
			return nil, err
		}
	}

	return a.encryptionKey, nil
}

func (a *ADAddress) HasLocation() bool {
	return (a.location != "")
}

func (a *ADAddress) ToString() string {
	return a.address
}

func (a *ADAddress) getAddressRequest() *airdispatch.AddressRequest {
	if a.address == "" {
		newQuery := &airdispatch.AddressRequest{
			Username: &a.username,
		}
		return newQuery

	} else {
		newQuery := &airdispatch.AddressRequest{
			Address: &a.address,
		}
		return newQuery
	}
}

func (a *ADKey) ToAddress() *ADAddress {
	return CreateADAddress(a.HexEncode())
}
