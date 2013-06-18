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
	MailServer string
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

	toSend, err := common.CreateAirdispatchMessage(regData, c.Key, mesType)
	if err != nil {
		return err
	}

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

	messageRequest := &airdispatch.RetrieveData {
		RetrievalType: common.RETRIEVAL_TYPE_PUBLIC(),
		FromAddress: &toCheck,
		SinceDate: &since,
	}

	return c.getMessagesWithRetrieval(messageRequest,
		func(inputData[]byte) (outputData *airdispatch.Mail, error error) {
			theMessage := &airdispatch.Mail{}
			proto.Unmarshal(inputData, theMessage)

			return theMessage, nil
		}, recipientServer)
}

func (c *Client) DownloadInbox(since uint64) ([]*airdispatch.Mail, error) {

	// Create the message to download the mail
	newDownloadRequest := &airdispatch.RetrieveData {
		RetrievalType: common.RETRIEVAL_TYPE_MINE(),
		SinceDate: &since,
	}

	return c.getMessagesWithRetrieval(newDownloadRequest,
		func(inputData[]byte) (outputData *airdispatch.Mail, error error) {
			newAlert := &airdispatch.Alert{}
			proto.Unmarshal(inputData, newAlert)

			// Print the contents of the Alert
			// fmt.Println("Received ALE from", newAlert, err)
			return c.DownloadSpecificMessageFromServer(*newAlert.MessageId, *newAlert.Location)
		}, c.MailServer)
}

type messageRetriever func(inputData []byte) (outputMessage *airdispatch.Mail, error error)

func (c *Client) getMessagesWithRetrieval(serverMessage *airdispatch.RetrieveData, retriever messageRetriever, server string) ([]*airdispatch.Mail, error) {
	// Connect to the mailserver
	mailServer, err := common.ConnectToServer(server)
	if err != nil {
		return nil, err
	}
	defer mailServer.Close()

	// Create the Message
	retData, err := proto.Marshal(serverMessage)
	if err != nil {
		return nil, err
	}

	toSend, err := common.CreateAirdispatchMessage(retData, c.Key, common.RETRIEVAL_MESSAGE)
	if err != nil {
		return nil, err
	}

	// Send the Message
	mailServer.Write(toSend)

	// Read the Signed Server Response
	data, messageType, _, err := common.ReadSignedMessage(mailServer)
	if err != nil {
		return nil, err
	}

	// Ensure that we have been given an array of values
	if messageType == common.ARRAY_MESSAGE {
		// Get the array from the data
		theArray := &airdispatch.ArrayedData{}
		proto.Unmarshal(data, theArray)

		outputMessages := []*airdispatch.Mail{}

		// Find the number of messsages
		mesNumber := theArray.NumberOfMessages

		// Loop over this number
		for i := uint32(0); i < *mesNumber; i++ {
			// Get the message and unmarshal it
			mesData, err := common.ReadAirdispatchMessage(mailServer)
			if err != nil {
				continue
			}

			theMessage, err := retriever(mesData)
			if err != nil {
				continue
			}

			outputMessages = append(outputMessages, theMessage)
		}

		return outputMessages, nil
	}
	return nil, errors.New("Did Not Return Correct Message Type Array, Instead" + messageType)
}

func (c *Client) DownloadSpecificMessageFromServer(messageId string, server string) (*airdispatch.Mail, error) {
	// Now, get the contents of that message
	getMessage := &airdispatch.RetrieveData {
		RetrievalType: common.RETRIEVAL_TYPE_NORMAL(),
		MessageId: &messageId,
	}

	getData, err := proto.Marshal(getMessage)
	if err != nil {
		return nil, err
	}

	sendData, err := common.CreateAirdispatchMessage(getData, c.Key, common.RETRIEVAL_MESSAGE)
	if err != nil {
		return nil, err
	}

	// Send the retrieval request
	remConn, err := common.ConnectToServer(server)
	if err != nil {
		return nil, err
	}
	defer remConn.Close()

	remConn.Write(sendData)

	// Get the MAI response and unmarshal it
	theMessageData, dataType, _, err := common.ReadSignedMessage(remConn)
	if err != nil {
		return nil, err
	}
	if dataType != common.MAIL_MESSAGE {
		return nil, errors.New("The Returned Message is not of MAI format.")
	}

	theMessage := &airdispatch.Mail{}
	proto.Unmarshal(theMessageData, theMessage)

	return theMessage, nil
}

func (c *Client) SendMail(toAddresses []string, theMail []byte) error {
	// Connect to the Remote Mailserver
	mail_conn, err := common.ConnectToServer(c.MailServer)
	if err != nil {
		return err
	}
	defer mail_conn.Close()

	// TODO: Allow sending to Multiple Recipients
	// Load the Send Request with the MailMessage
	sendRequest := &airdispatch.SendMailRequest {
		ToAddress: toAddresses,
		StoredMessage: theMail,
	}

	// Convert the Structure into Bytes
	sendBytes, err := proto.Marshal(sendRequest)
	if err != nil {
		return err
	}

	mesType := common.SEND_REQUEST
	toSend, err := common.CreateAirdispatchMessage(sendBytes, c.Key, mesType)
	if err != nil {
		return err
	}

	// Send the Message
	mail_conn.Write(toSend)
	return nil
}
