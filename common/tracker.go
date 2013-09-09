package common

import (
	"airdispat.ch/airdispatch"
	"code.google.com/p/goprotobuf/proto"
	"crypto/rsa"
	"errors"
	"net"
	"strings"
	"time"
)

// SECTION ON TRACKER OBJECT

type ADTracker struct {
	tracker_url         string
	tracker_fingerprint string
}

func CreateADTracker(tracker_url string) *ADTracker {
	output := &ADTracker{}

	if tracker_url == "" {
		return nil
	}

	output.tracker_url = tracker_url
	return output
}

func (a *ADTracker) IsResponding() bool {
	return false
}

func (a *ADTracker) QueryForAddress(address *ADAddress, key *ADKey) (*ADQueryResponse, error) {
	// Create a new Query Message
	newQuery := address.getAddressRequest()

	// Set the Message Type and get the Bytes of the Message
	queryData, err := proto.Marshal(newQuery)
	if err != nil {
		return nil, err
	}

	// Create the Message to be sent over the wire
	newMessage := &ADMessage{
		Payload:     queryData,
		MessageType: QUERY_MESSAGE,
	}

	readMessage, err := newMessage.SendToServerWithResponse(a.tracker_url, key)
	if err != nil {
		return nil, err
	}

	expectedAddress, err := VerifyTrackerAddress(a.tracker_url)
	if err == nil {
		if expectedAddress != readMessage.FromAddress.ToString() {
			return nil, ADTrackerVerificationError
		}
		a.tracker_fingerprint = expectedAddress
	}

	if readMessage.MessageType != QUERY_RESPONSE_MESSAGE {
		return nil, ADUnexpectedMessageTypeError
	}

	// Unmarshal the Response
	newQueryResponse := &airdispatch.AddressResponse{}
	proto.Unmarshal(readMessage.Payload, newQueryResponse)

	rKey, err := BytesToRSA(newQueryResponse.PublicKey)
	if err != nil {
		return nil, err
	}

	output := &ADQueryResponse{
		Location:       *newQueryResponse.ServerLocation,
		PublicKey:      rKey,
		EncodedAddress: *newQueryResponse.Address,
	}

	return output, nil
}

func (a *ADTracker) RegisterAddress(key *ADKey, mailserver string) error {
	mesType := REGISTRATION_MESSAGE
	byteKey := RSAToBytes(&key.EncryptionKey.PublicKey)

	currentTime := uint64(time.Now().Unix())
	address := key.HexEncode()

	// Create the Registration Message
	newRegistration := &airdispatch.AddressRegistration{
		Address:   &address,
		PublicKey: byteKey,
		Location:  &mailserver,
		Timestamp: &currentTime,
	}

	// Create the Signed Message
	regData, err := proto.Marshal(newRegistration)
	if err != nil {
		return err
	}

	newMessage := &ADMessage{
		Payload:     regData,
		MessageType: mesType,
	}

	_, err = newMessage.SendToServerWithResponse(a.tracker_url, key)
	if err != nil {
		return err
	}

	return nil
}

func VerifyTrackerAddress(tracker string) (string, error) {
	records, err := net.LookupTXT(tracker)
	if err != nil {
		return "", errors.New("Couldn't fetch TXT Records")
	}

	for _, v := range records {
		if strings.HasPrefix(v, "adtp__cert:") {
			return strings.TrimPrefix(v, "adtp__cert:"), nil
		}
	}

	return "", errors.New("Couldn't Find Certificate")
}

// SECTION FOR TRACKER LIST

type ADTrackerList struct {
	trackers []*ADTracker
}

func CreateADTrackerList(trackers ...*ADTracker) *ADTrackerList {
	output := &ADTrackerList{}

	if trackers == nil {
		return nil
	}

	output.trackers = trackers
	return output
}

func CreateADTrackerListWithStrings(trackers ...string) *ADTrackerList {
	output := &ADTrackerList{}
	trackerList := make([]*ADTracker, len(trackers))

	for i, v := range trackers {
		trackerList[i] = CreateADTracker(v)
	}

	output.trackers = trackerList
	return output
}

func (a *ADTrackerList) Query(address *ADAddress, key *ADKey) (*ADQueryResponse, error) {
	data := make(chan *ADQueryResponse)
	errChan := make(chan error)
	timeout := make(chan bool)

	go func() {
		time.Sleep(ADTimeoutSeconds * time.Second)
		timeout <- true
	}()

	queryFunction := func(c chan *ADQueryResponse, t *ADTracker) {
		response, err := t.QueryForAddress(address, key)
		if err != nil {
			errChan <- err
			return
		}

		c <- response
	}

	for _, tracker := range a.trackers {
		go queryFunction(data, tracker)
	}

	errorCount := 0

	for errorCount < len(a.trackers) {
		select {
		case d := <-data:
			return d, nil
		case <-errChan:
			errorCount++
		case <-timeout:
			return nil, ADTimeoutError
		}
	}
	return nil, ADTrackerListQueryError
}

// This is non-deterministic... Yes. That isn't the correct word. Sorry.
func (a *ADTrackerList) Register(key *ADKey, mailserver string) error {
	for _, tracker := range a.trackers {
		go tracker.RegisterAddress(key, mailserver)
	}
	return nil
}

// NECESSARY TYPES

type ADQueryResponse struct {
	Location       string
	PublicKey      *rsa.PublicKey
	EncodedAddress string
}
