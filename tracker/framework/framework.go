package framework

import (
	"airdispat.ch/airdispatch"
	"airdispat.ch/common"
	"code.google.com/p/goprotobuf/proto"
	"net"
)

// This data type holds all of the information needed
// to store each tracker entry
type TrackerRecord struct {
	PublicKey []byte
	Location  string
	Username  string
	Address   *common.ADAddress
}

// The error Structure used to store all of the
// errors generated by the tracker framework
type TrackerError struct {
	Location string
	Error    error
}

// The delegate protocol used to interact with a specific tracker
// implementation
type TrackerDelegate interface {
	HandleError(err *TrackerError)
	LogMessage(toLog string)
	AllowConnection(fromAddr *common.ADAddress) bool

	SaveTrackerRecord(record *TrackerRecord)

	GetRecordByUsername(username string) *TrackerRecord
	GetRecordByAddress(address string) *TrackerRecord
}

// The tracker structure that holds variables to the delegate
// and keypair.
type Tracker struct {
	Key      *common.ADKey
	Delegate TrackerDelegate
}

// The function that starts the Tracking Server on a Specific Port
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

// Called when the Tracker runs into an error. It reports the error to the delegate.
func (t *Tracker) handleError(location string, error error) {
	t.Delegate.HandleError(&TrackerError{
		Location: location,
		Error:    error,
	})
}

// This is the loop used while the Tracker waits for clients to connect.
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

// Called when the tracker connects to a client.
func (t *Tracker) handleClient(conn net.Conn) {
	defer conn.Close()

	// Read in the Message Sent from the Client
	newMessage, err := common.CreateADMessageFromConnection(conn)
	if err != nil {
		t.handleError("Handle Client (Reading in Message)", err)
		return
	}

	// Determine how to Proceed based on the Message Type
	switch newMessage.MessageType {

	// Handle Registration
	case common.REGISTRATION_MESSAGE:
		// Unmarshal the Sent Data
		assigned := &airdispatch.AddressRegistration{}
		err := proto.Unmarshal(newMessage.Payload, assigned)
		if err != nil {
			t.handleError("Handle Client (Unloading Registration Payload)", err)
			return
		}

		t.handleRegistration(newMessage.FromAddress, assigned)

	// Handle Query
	case common.QUERY_MESSAGE:
		// Unmarshall the Sent Data
		assigned := &airdispatch.AddressRequest{}
		err := proto.Unmarshal(newMessage.Payload, assigned)
		if err != nil {
			t.handleError("Handle Client (Unloading Query Payload)", err)
			return
		}

		t.handleQuery(newMessage.FromAddress, assigned, conn)
	}
}

func (t *Tracker) handleRegistration(theAddress *common.ADAddress, reg *airdispatch.AddressRegistration) {
	// Check to see if a Username was provided
	username := ""
	if reg.Username != nil && *reg.Username != "" {
		username = *reg.Username
	}

	// Load the RegisteredAddress with the sent information
	data := &TrackerRecord{
		PublicKey: reg.PublicKey,
		Location:  *reg.Location,
		Username:  username,
		Address:   theAddress,
	}

	t.Delegate.SaveTrackerRecord(data)
}

func (t *Tracker) handleQuery(theAddress *common.ADAddress, req *airdispatch.AddressRequest, conn net.Conn) {
	var info *TrackerRecord
	if req.Username != nil && *req.Username != "" {
		info = t.Delegate.GetRecordByUsername(*req.Username)
	} else {
		info = t.Delegate.GetRecordByAddress(*req.Address)
	}

	// Return an Error Message if we could not find the address
	if info == nil {
		common.CreateErrorMessage("400", "Couldn't find that Address at this Tracker.").SendToConnection(conn, t.Key)
		return
	}

	// Create a Formatted Message
	response := &airdispatch.AddressResponse{
		ServerLocation: &info.Location,
		Address:        req.Address,
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

	newMessage := &common.ADMessage{
		Payload:     data,
		MessageType: common.QUERY_RESPONSE_MESSAGE,
	}

	newMessage.SendToConnection(conn, t.Key)
}
