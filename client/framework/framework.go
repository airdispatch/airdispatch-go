package framework

import (
	"airdispat.ch/airdispatch"
	"airdispat.ch/common"
	"code.google.com/p/goprotobuf/proto"
	"errors"
	"time"
)

// This structure is the foundation of the Client-framework package
// as all of the following methods are defined on it.
type Client struct {
	Address    string        // The Airdispatch Address of the User represented by this structure
	Key        *common.ADKey // The ECDSA Keypair of the User represented by this structure
	MailServer string        // The Mailserver associated with the User represented by this structure
}

// This function populates the Address portion of the Client structure
// by providing the ADKey
func (c *Client) Populate(key *common.ADKey) {
	c.Key = key
	c.Address = key.HexEncode()
}

// This function is used to Register a Client with a Tracker
func (c *Client) SendRegistration(tracker string) error {
	// Connect to the Tracking Server
	tracker_conn, err := common.ConnectToServer(tracker)
	if err != nil {
		return err
	}
	defer tracker_conn.Close()

	mesType := common.REGISTRATION_MESSAGE
	byteKey := common.RSAToBytes(&c.Key.EncryptionKey.PublicKey)

	currentTime := uint64(time.Now().Unix())

	// Create the Registration Message
	newRegistration := &airdispatch.AddressRegistration{
		Address:   &c.Address,
		PublicKey: byteKey,
		Location:  &c.MailServer,
		Timestamp: &currentTime,
	}

	// Create the Signed Message
	regData, err := proto.Marshal(newRegistration)
	if err != nil {
		return err
	}

	newMessage := &common.ADMessagePrimative{regData, mesType, ""}

	toSend, err := c.Key.CreateADMessagePrimative(newMessage)
	if err != nil {
		return err
	}

	// Send the Message
	tracker_conn.Write(toSend)
	return nil
}

// This function downloads public mail from an Address given a list of trackers
func (c *Client) DownloadPublicMail(trackingServers []string, toCheck string, since uint64) ([]*airdispatch.Mail, error) {
	// Get the Server where the Public Mail Resides (And Connect to It)
	recipientServer, _, err := common.LookupLocation(toCheck, trackingServers, c.Key)
	if err != nil {
		return nil, err
	}

	messageRequest := &airdispatch.RetrieveData{
		RetrievalType: common.ADRetrievalPublic,
		FromAddress:   &toCheck,
		SinceDate:     &since,
	}

	return c.getMessagesWithRetrieval(messageRequest,
		func(inputData []byte) (outputData *airdispatch.Mail, error error) {
			theMessage := &airdispatch.Mail{}
			proto.Unmarshal(inputData, theMessage)

			return theMessage, nil
		}, recipientServer)
}

func (c *Client) DownloadInbox(since uint64) ([]*airdispatch.Mail, error) {

	// Create the message to download the mail
	newDownloadRequest := &airdispatch.RetrieveData{
		RetrievalType: common.ADRetrievalMine,
		SinceDate:     &since,
	}

	return c.getMessagesWithRetrieval(newDownloadRequest,
		func(inputData []byte) (outputData *airdispatch.Mail, error error) {
			newAlert := &airdispatch.Alert{}
			proto.Unmarshal(inputData, newAlert)

			// Print the contents of the Alert
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

	newMessage := &common.ADMessagePrimative{retData, common.RETRIEVAL_MESSAGE, ""}

	toSend, err := c.Key.CreateADMessagePrimative(newMessage)
	if err != nil {
		return nil, err
	}

	// Send the Message
	mailServer.Write(toSend)

	// Read the Signed Server Response
	_, reADMessagePrimative, err := common.ReadADMessagePrimative(mailServer)
	if err != nil {
		return nil, err
	}

	// Ensure that we have been given an array of values
	if reADMessagePrimative.MessageType == common.ARRAY_MESSAGE {
		// Get the array from the data
		theArray := &airdispatch.ArrayedData{}
		proto.Unmarshal(reADMessagePrimative.Payload, theArray)

		outputMessages := []*airdispatch.Mail{}

		// Find the number of messsages
		mesNumber := theArray.NumberOfMessages

		// Loop over this number
		for i := uint32(0); i < *mesNumber; i++ {
			// Get the message and unmarshal it
			_, retrievedMessage, err := common.ReadADMessagePrimative(mailServer)
			if err != nil {
				continue
			}

			theMessage, err := retriever(retrievedMessage.Payload)
			if err != nil {
				continue
			}

			if retrievedMessage.MessageType == common.MAIL_MESSAGE {
				if *theMessage.FromAddress != retrievedMessage.FromAddress {
					continue
				}
			} else if retrievedMessage.MessageType == common.ALERT_MESSAGE {
				// No Alert Validation
			} else {
				continue
			}

			outputMessages = append(outputMessages, theMessage)
		}

		return outputMessages, nil
	}
	return nil, errors.New("Did Not Return Correct Message Type Array, Instead" + reADMessagePrimative.MessageType)
}

// This function downloads a Message with ID from a Server server
func (c *Client) DownloadSpecificMessageFromServer(messageId string, server string) (*airdispatch.Mail, error) {
	// Now, get the contents of that message
	getMessage := &airdispatch.RetrieveData{
		RetrievalType: common.ADRetrievalNormal,
		MessageId:     &messageId,
	}

	getData, err := proto.Marshal(getMessage)
	if err != nil {
		return nil, err
	}

	newMessage := &common.ADMessagePrimative{getData, common.RETRIEVAL_MESSAGE, ""}

	sendData, err := c.Key.CreateADMessagePrimative(newMessage)
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
	_, reADMessagePrimative, err := common.ReadADMessagePrimative(remConn)
	if err != nil {
		return nil, err
	}
	if reADMessagePrimative.MessageType != common.MAIL_MESSAGE {
		return nil, errors.New("The Returned Message is not of MAI format.")
	}

	theMessage := &airdispatch.Mail{}
	proto.Unmarshal(reADMessagePrimative.Payload, theMessage)

	return theMessage, nil
}

// This function sends mail to addresses
func (c *Client) SendMail(toAddresses []string, theMail []byte) error {
	// Connect to the Remote Mailserver
	mail_conn, err := common.ConnectToServer(c.MailServer)
	if err != nil {
		return err
	}
	defer mail_conn.Close()

	// TODO: Allow sending to Multiple Recipients
	// Load the Send Request with the MailMessage
	sendRequest := &airdispatch.SendMailRequest{
		ToAddress:     toAddresses,
		StoredMessage: theMail,
	}

	// Convert the Structure into Bytes
	sendBytes, err := proto.Marshal(sendRequest)
	if err != nil {
		return err
	}

	newMessage := &common.ADMessagePrimative{sendBytes, common.SEND_REQUEST, ""}

	toSend, err := c.Key.CreateADMessagePrimative(newMessage)
	if err != nil {
		return err
	}

	// Send the Message
	mail_conn.Write(toSend)
	return nil
}
