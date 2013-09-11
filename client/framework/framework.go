package framework

import (
	"airdispat.ch/airdispatch"
	"airdispat.ch/common"
	"code.google.com/p/goprotobuf/proto"
)

// This structure is the foundation of the Client-framework package
// as all of the following methods are defined on it.
type Client struct {
	Key        *common.ADKey // The ECDSA Keypair of the User represented by this structure
	MailServer string        // The Mailserver associated with the User represented by this structure
}

// This function populates the Address portion of the Client structure
// by providing the ADKey
func (c *Client) Populate(key *common.ADKey) {
	c.Key = key
}

// This function is used to Register a Client with a Tracker
func (c *Client) SendRegistration(tracker string) error {
	theTracker := common.CreateADTracker(tracker)
	err := theTracker.RegisterAddress(c.Key, c.MailServer)
	return err
}

// This function downloads public mail from an Address given a list of trackers
func (c *Client) DownloadPublicMail(trackingServers *common.ADTrackerList, toCheck *common.ADAddress, since uint64) ([]*common.ADMail, error) {
	// Get the Server where the Public Mail Resides (And Connect to It)
	recipientServer, err := toCheck.GetLocation(c.Key, trackingServers)
	if err != nil {
		return nil, err
	}

	theAddress := toCheck.ToString()

	messageRequest := &airdispatch.RetrieveData{
		RetrievalType: common.ADRetrievalPublic,
		FromAddress:   &theAddress,
		SinceDate:     &since,
	}

	return c.getMessagesWithRetrieval(messageRequest, recipientServer)
}

func (c *Client) DownloadInbox(since uint64) ([]*common.ADMail, error) {

	// Create the message to download the mail
	newDownloadRequest := &airdispatch.RetrieveData{
		RetrievalType: common.ADRetrievalMine,
		SinceDate:     &since,
	}

	return c.getMessagesWithRetrieval(newDownloadRequest, c.MailServer)
}

type messageRetriever func(inputData []byte) (outputMessage *airdispatch.Mail, error error)

func (c *Client) getMessagesWithRetrieval(serverMessage *airdispatch.RetrieveData, server string) ([]*common.ADMail, error) {
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

	newMessage := &common.ADMessage{
		Payload:     retData,
		MessageType: common.RETRIEVAL_MESSAGE,
	}

	err = newMessage.SendToConnection(mailServer, c.Key)
	if err != nil {
		return nil, err
	}

	response, err := common.CreateADMessageFromConnection(mailServer)
	if err != nil {
		return nil, err
	}

	// Ensure that we have been given an array of values
	if response.MessageType == common.ARRAY_MESSAGE {
		// Get the array from the data
		theArray := &airdispatch.ArrayedData{}
		proto.Unmarshal(response.Payload, theArray)

		outputMessages := []*common.ADMail{}

		// Find the number of messsages
		mesNumber := theArray.NumberOfMessages

		// Loop over this number
		for i := uint32(0); i < *mesNumber; i++ {
			// Get the message and unmarshal it
			retrievedMessage, err := common.CreateADMessageFromConnection(mailServer)
			if err != nil {
				continue
			}

			var theMail *common.ADMail
			if retrievedMessage.MessageType == common.MAIL_MESSAGE {
				theMail, err = common.CreateADMailFromADMessage(retrievedMessage, c.Key)
				if err != nil {
					continue
				}

			} else if retrievedMessage.MessageType == common.ALERT_MESSAGE {
				theAlert, err := common.CreateADAlertFromADMessage(retrievedMessage)
				if err != nil {
					continue
				}

				theMail, err = theAlert.GetMail(c.Key)
				if err != nil {
					continue
				}

			} else {
				continue
			}

			if theMail != nil {
				outputMessages = append(outputMessages, theMail)
			}
		}

		return outputMessages, nil
	}
	return nil, common.ADUnexpectedMessageTypeError
}

// This function downloads a Message with ID from a Server server
func (c *Client) DownloadSpecificMessageFromServer(messageId string, server string) (*common.ADMail, error) {
	return common.CreateADAlertBasic(messageId, server).GetMail(c.Key)
}

// This function sends mail to addresses
func (c *Client) SendMail(toAddress *common.ADAddress, theMail *common.ADMail, trackerList *common.ADTrackerList) error {
	// Load the Send Request with the MailMessage
	theMessage, err := theMail.Marshal(toAddress, c.Key, trackerList)
	if err != nil {
		return err
	}

	signedBytes, err := theMessage.MarshalToBytes(c.Key, false)
	if err != nil {
		return err
	}

	sendRequest := &airdispatch.SendMailRequest{
		ToAddress:     []string{toAddress.ToString()},
		StoredMessage: signedBytes,
	}

	// Convert the Structure into Bytes
	sendBytes, err := proto.Marshal(sendRequest)
	if err != nil {
		return err
	}

	newMessage := &common.ADMessage{
		Payload:     sendBytes,
		MessageType: common.SEND_REQUEST,
	}
	err = newMessage.SendToServer(c.MailServer, c.Key)
	return err
}

func mapAddressesToStrings(theAddress []*common.ADAddress) []string {
	output := make([]string, len(theAddress))
	for i, v := range theAddress {
		output[i] = v.ToString()
	}
	return output
}
