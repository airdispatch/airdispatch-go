package framework;

import (
	"code.google.com/p/goprotobuf/proto"
	"airdispat.ch/airdispatch"
	"airdispat.ch/common"
	"crypto/ecdsa"
	"errors"
)

type Client struct {
	Address string
	Key *ecdsa.PrivateKey
}

func (c *Client) Populate(key *ecdsa.PrivateKey) {
	c.Key = key
	c.Address = common.StringAddress(&key.PublicKey)
}

func (c *Client) SendRegistration(tracker string, location string) error {
	// Connect to the Tracking Server
	tracker_conn, err := common.ConnectToServer(tracker)
	if err != nil {
		return err
	}
	defer tracker_conn.Close()

	mesType := common.REGISTRATION_MESSAGE
	byteKey := common.KeyToBytes(&c.Key.PublicKey)

	// Create the Registration Message
	newRegistration := &airdispatch.AddressRegistration{
		Address: &c.Address,
		PublicKey: byteKey,
		Location: &location,
	}

	// Create the Signed Message
	regData, err := proto.Marshal(newRegistration)
	if err != nil {
		return err
	}

	toSend := common.CreateAirdispatchMessage(regData, c.Key, mesType)

	// Send the Message
	tracker_conn.Write(toSend)
	return nil
}

func (c *Client) DownloadPublicMail(trackingServers []string, toCheck string, since uint64) ([]*airdispatch.Mail, error) {
	// Get the Server where the Public Mail Resides (And Connect to It)
	recipientServer, err := common.LookupLocation(toCheck, trackingServers, c.Key)
	if err != nil {
		return nil, err
	}

	recipientConn, err := common.ConnectToServer(recipientServer)
	if err != nil {
		return nil, err
	}

	// Create the Request Object
	messageRequest := &airdispatch.RetrieveData {
		RetrievalType: common.RETRIEVAL_TYPE_PUBLIC(),
		FromAddress: &toCheck,
		SinceDate: &since,
	}
	requestData, _ := proto.Marshal(messageRequest)
	sendData := common.CreateAirdispatchMessage(requestData, c.Key, common.RETRIEVAL_MESSAGE)

	// Send the Request to the Server
	recipientConn.Write(sendData)

	// Read the Message Response
	data, messageType, _, err := common.ReadSignedMessage(recipientConn)
	if err != nil {
		return nil, err
	}

	// Ensure that we have been given an array of values
	if messageType == common.ARRAY_MESSAGE {
		// Get the array from the data
		theArray := &airdispatch.ArrayedData{}
		proto.Unmarshal(data, theArray)

		outputMessages := []*airdispatch.Mail{}

		// Loop over this number
		for i := uint32(0); i < *theArray.NumberOfMessages; i++ {
			// Get the message and unmarshal it
			mesData, _, _, _ := common.ReadSignedMessage(recipientConn)
			theMessage := &airdispatch.Mail{}
			proto.Unmarshal(mesData, theMessage)

			// Print the Message
			outputMessages = append(outputMessages, theMessage)
		}
		return outputMessages, nil
	}
	return nil, errors.New("Did Not Return Correct Message Type Array, Instead" + messageType)
}
