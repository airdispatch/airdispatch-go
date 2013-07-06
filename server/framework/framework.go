package framework

import (
	"net"
	"airdispat.ch/common"
	"airdispat.ch/airdispatch"
	"code.google.com/p/goprotobuf/proto"
	"crypto/ecdsa"
	"bytes"
	"errors"
)

type ServerError struct {
	Location string
	Error error
}

type ServerDelegate interface {
	HandleError(err *ServerError)
	LogMessage(toLog string)

	SavePublicMail(mailData []byte, fromAddress string)
	SavePrivateMail(mailData []byte, toAddresses []string) (messageId string)

	SaveIncomingAlert(alert *airdispatch.Alert, alertData []byte, fromAddr string)

	AllowConnection(fromAddr string) bool

	RetrieveMessage(id string) (message []byte, approvedRecipients []string)
	RetrievePublic(fromAddr string, since uint64) (messages [][]byte)
	RetrieveInbox(addr string, since uint64) (messages [][]byte)
}

type Server struct {
	LocationName string
	TrackerList []string
	Key *ecdsa.PrivateKey
	Delegate ServerDelegate
}

func (s *Server) StartServer(port string) (error) {
	// Resolve the Address of the Server
	service := ":" + port
	tcpAddr, _ := net.ResolveTCPAddr("tcp4", service)
	s.Delegate.LogMessage("Starting Server on " + service)

	// Start the Server
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}
	s.Delegate.LogMessage("Server is Running...")

	s.serverLoop(listener)
	return nil
}

func (s *Server) handleError(location string, error error) {
	s.Delegate.HandleError(&ServerError {
		Location: location,
		Error: error,
	})
}

func (s *Server) serverLoop(listener *net.TCPListener) {
	// Loop forever, waiting for connections
	for {
		// Accept a Connection
		conn, err := listener.Accept()
		if err != nil {
			s.handleError("Server Loop (Accepting New Client)", err)
			continue
		}

		// Concurrently handle the connection
		go s.handleClient(conn)
	}	
}

func (s *Server) handleClient(conn net.Conn) {
	// Close the Connection after Handling
	defer conn.Close()

	// Read in the Message
	payload, totalBytes, messageType, theAddress, err := common.ReadTotalMessage(conn)
	if err != nil {
		s.handleError("Handle Client (Reading Signed Message)", err)
		return
	}

	if !s.Delegate.AllowConnection(theAddress) {
		return
	}

	// Switch based on the Message Type
	switch messageType {

		case common.ALERT_MESSAGE:
			// Unmarshal the stored message
			assigned := &airdispatch.Alert{}
			err := proto.Unmarshal(payload, assigned)
			if err != nil {
				s.handleError("Handle Client (Unloading Alert Payload)", err)
				return
			}

			// Handle the Alert
			s.handleAlert(assigned, totalBytes, theAddress)

		case common.RETRIEVAL_MESSAGE:
			// Unmarshal the stored message
			assigned := &airdispatch.RetrieveData{}
			err := proto.Unmarshal(payload, assigned)
			if err != nil {
				s.handleError("Handle Client (Unloading Retrieval Payload)", err)
				return
			}

			// Handle the Retrieval Message
			s.handleRetrieval(assigned, theAddress, conn)

		case common.SEND_REQUEST:
			// Unmarshal the stored message
			assigned := &airdispatch.SendMailRequest{}
			err := proto.Unmarshal(payload, assigned)
			if err != nil {
				s.handleError("Handle Client (Unloading Send Request Payload)", err)
				return
			}

			// Handle the Send Request
			s.handleSendRequest(assigned, theAddress)
	}
}

// Function that Handles an Alert of a Message
func (s *Server) handleAlert(alert *airdispatch.Alert, alertData []byte, fromAddr string) {
	s.Delegate.SaveIncomingAlert(alert, alertData, fromAddr)
}

// Function that Handles a DataRetrieval Message
func (s *Server) handleRetrieval(retrieval *airdispatch.RetrieveData, toAddr string, conn net.Conn) {
	// Get the Type of the Message and Switch on it
	c := retrieval.RetrievalType
	switch {
		// Receieved a Normal Retrieval Message (Lookup the Message ID)
		case bytes.Equal(c, common.RETRIEVAL_TYPE_NORMAL()):
			message, approved := s.Delegate.RetrieveMessage(*retrieval.MessageId)

			if message == nil {
				// If there is no message stored with that ID, then send back an error
				conn.Write(common.CreateErrorMessage("no message for that id"))
				return
			}

			// Check that the Sending Address is one of the Approved Recipients
			if !common.SliceContains(approved, toAddr) {
				conn.Write(common.CreateErrorMessage("not an approved recipient"))
				return
			}

			// If it passes these checks, send the message back through the connection
			conn.Write(common.CreatePrefixedMessage(message))

		// Received a Public Retrieval Message (Return all Messages Since the Date Provided)
		case bytes.Equal(c, common.RETRIEVAL_TYPE_PUBLIC()):

			output := s.Delegate.RetrievePublic(*retrieval.FromAddress, *retrieval.SinceDate)

			if len(output) == 0 {
				conn.Write(common.CreateErrorMessage("no public messages for that address"))
				return
			}

			// Alert the Client that an Array is Coming
			arrayData, err := common.CreateArrayedMessage(uint32(len(output)), s.Key)
			if err != nil {
				s.handleError("Handle Retrieval (Creating AD Message)", err)
				return
			}

			conn.Write(arrayData)

			// Write all of the Data
			for _, v := range(output) {
				conn.Write(common.CreatePrefixedMessage(v))
			}

		// Received a Mine Retrieval Message (Return all Messages that are Stored - Since the Date Provided)	
		case bytes.Equal(c, common.RETRIEVAL_TYPE_MINE()):
			output := s.Delegate.RetrieveInbox(toAddr, *retrieval.SinceDate)

			if len(output) == 0 {
				conn.Write(common.CreateErrorMessage("no inbox messages for that address"))
				return
			}

			arrayData, err := common.CreateArrayedMessage(uint32(len(output)), s.Key)
			if err != nil {
				s.handleError("Handle Retrieval (Creating AD Message)", err)
				return
			}

			conn.Write(arrayData)

			// Write all of the Data
			for _, v := range(output) {
				conn.Write(common.CreatePrefixedMessage(v))
			}

		default:
			s.handleError("Handle Retrieval", errors.New("Invalid Retrieval Type"))
	}
}

// Function that Handles a Request to Send a Message
func (s *Server) handleSendRequest(request *airdispatch.SendMailRequest, fromAddr string) {
	// Check to see if it a public message or not
	if len(request.ToAddress) != 0 && request.ToAddress[0] != fromAddr && request.ToAddress[0] != "" {
		hash := s.Delegate.SavePrivateMail(request.StoredMessage, request.ToAddress)

		for _, v := range(request.ToAddress) {
			// For every address that the Message is to be sent to, lookup its location and send it an alert
			loc, err := common.LookupLocation(v, s.TrackerList, s.Key)
			if err != nil {
				s.handleError("Handle Send Request (Lookup Address)", errors.New("Address Lookup Failed"))
				return
			}

			s.SendAlert(loc, hash, v)
		}

	} else {
		s.Delegate.SavePublicMail(request.StoredMessage, fromAddr)
	}
}

// A function that delivers an alert to a location
func (s *Server) SendAlert(location string, message_id string, toAddr string) {
	conn, err := common.ConnectToServer(location)
	if err != nil {
		s.handleError("Send Alert", errors.New("Unable to Connect to Server"))
		return
	}

	// Populate the Alert message
	newAlert := &airdispatch.Alert {
		ToAddress: &toAddr,
		Location: &s.LocationName,
		MessageId: &message_id,
	}
	alertData, _ := proto.Marshal(newAlert)

	// Create the Message to Send
	bytesToSend, err := common.CreateAirdispatchMessage(alertData, s.Key, common.ALERT_MESSAGE)
	if err != nil {
		s.handleError("Send Alert (Create AD Message)", err)
		return
	}

	// Write the Message
	conn.Write(bytesToSend)
	conn.Close()
}
