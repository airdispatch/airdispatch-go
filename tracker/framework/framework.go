package framework

import (
	"net"
	"crypto/ecdsa"
	"airdispat.ch/common"
	"airdispat.ch/airdispatch"
	"code.google.com/p/goprotobuf/proto"
)

type TrackerRecord struct {
	PublicKey []byte
	Location string
	Username string
	Address string
}

type TrackerError struct {
	Location string
	Error error
}

type TrackerDelegate interface {
	HandleError(err *TrackerError)
	LogMessage(toLog string)
	AllowConnection(fromAddr string) bool

	SaveTrackerRecord(record *TrackerRecord)

	GetRecordByUsername(username string) *TrackerRecord
	GetRecordByAddress(address string) *TrackerRecord
}

type Tracker struct {
	Key *ecdsa.PrivateKey
	Delegate TrackerDelegate
}

func (t *Tracker) StartServer(port string) error {
	// Resolve the Address of the Server
	service := ":" + port
	tcpAddr, _ := net.ResolveTCPAddr("tcp4", service)
	t.Delegate.LogMessage("Starting Tracker on " + service)

	// Start the Server
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}
	t.Delegate.LogMessage("Tracker is Running...")

	t.trackerLoop(listener)
	return nil
}

func (t *Tracker) handleError(location string, error error) {
	t.Delegate.HandleError(&TrackerError{
		Location: location,
		Error: error,
	})
}

func (t *Tracker) trackerLoop(listener *net.TCPListener) {
	// Loop Forever while we wait for Clients
	for {
		// Open a Connection to the Client
		conn, err := listener.Accept()
		if err != nil {
			t.handleError("Tracker Loop (Accepting New Client)", err)
			return
		}

		// Concurrently Handle the Connection
		go t.handleClient(conn)
	}
}

func (t *Tracker) handleClient(conn net.Conn) {
	defer conn.Close()

	// Read in the Message Sent from the Client
	data, messageType, theAddress, err := common.ReadSignedMessage(conn)
	if err != nil {
		t.handleError("Handle Client (Reading in Message)", err)
		return
	}

	// Determine how to Proceed based on the Message Type
	switch messageType {

		// Handle Registration
		case common.REGISTRATION_MESSAGE:
			// Unmarshal the Sent Data
			assigned := &airdispatch.AddressRegistration{}
			err := proto.Unmarshal(data, assigned)
			if err != nil {
				t.handleError("Handle Client (Unloading Registration Payload)", err)
				return
			}

			t.handleRegistration(theAddress, assigned) 

		// Handle Query
		case common.QUERY_MESSAGE:
			// Unmarshall the Sent Data
			assigned := &airdispatch.AddressRequest{}
			err := proto.Unmarshal(data, assigned)
			if err != nil {
				t.handleError("Handle Client (Unloading Query Payload)", err)
				return
			}

			t.handleQuery(theAddress, assigned, conn)
	}
}

func (t *Tracker) handleRegistration(theAddress string, reg *airdispatch.AddressRegistration) {
	// Check to see if a Username was provided
	username := ""
	if reg.Username != nil && *reg.Username != "" {
		username = *reg.Username
	}

	// Load the RegisteredAddress with the sent information
	data := &TrackerRecord{
		PublicKey: reg.PublicKey,
		Location: *reg.Location,
		Username: username,
		Address: theAddress,
	}

	t.Delegate.SaveTrackerRecord(data)
}

func (t *Tracker) handleQuery(theAddress string, req *airdispatch.AddressRequest, conn net.Conn) {
	var info *TrackerRecord
	if req.Username != nil && *req.Username != "" {
		info = t.Delegate.GetRecordByUsername(*req.Username)
	} else {
		info = t.Delegate.GetRecordByAddress(*req.Address)
	}

	// Return an Error Message if we could not find the address
	if info == nil {
		conn.Write(common.CreateErrorMessage("not located here"))
		return
	}

	// Create a Formatted Message
	response := &airdispatch.AddressResponse {
		ServerLocation: &info.Location,
		Address: &theAddress,
	}

	// If the requester does not want the public key, we should not provide it
	if req.NeedKey == nil && info.PublicKey != nil {
		response.PublicKey = info.PublicKey
	}

	data, err := proto.Marshal(response)
	if err != nil {
		t.handleError("Handle Query (Creating Response Object)", err)
		return
	}

	bytesToSend, err := common.CreateAirdispatchMessage(data, t.Key, common.QUERY_RESPONSE_MESSAGE)
	if err != nil {
		t.handleError("Send Alert (Create AD Message)", err)
		return
	}

	// Send the Response
	conn.Write(bytesToSend)
}