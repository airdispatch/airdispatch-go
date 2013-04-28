package main

import (
	"fmt"
	"net"
	"flag"
	"os"
	"strings"
	"airdispat.ch/common"
	"airdispat.ch/airdispatch"
	"code.google.com/p/goprotobuf/proto"
	"crypto/ecdsa"
	"encoding/hex"
)

var port = flag.String("port", "2048", "select the port on which to run the mail server")
var trackers = flag.String("trackers", "", "prepopulate the list of trackers that this server will query by using a comma seperated list of values")

var mailboxes map[string] Mailbox
type Mailbox map[string] Mail
type Mail struct {
	from string
	location string
}

var storedMessages map[string] MailData
type MailData struct {
	approved []string
	data []byte
}

var connectedTrackers []string
var serverLocation string
var serverKey *ecdsa.PrivateKey

func main() {
	flag.Parse()

	mailboxes = make(map[string]Mailbox)
	storedMessages = make(map[string]MailData)
	connectedTrackers = strings.Split(*trackers, ",")
	if (*trackers == "") { connectedTrackers = make([]string, 0) }
	serverKey, _ = common.CreateKey()

	serverLocation, _ = os.Hostname()

	service := ":" + *port
	tcpAddr, _ := net.ResolveTCPAddr("tcp4", service)

	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Unable to Listen for Requests")
		return
	}
	fmt.Println("Listening on", service)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
			fmt.Println("Unable to Connect to Client", conn.RemoteAddr())
		}

		go handleClient(conn)

	} 

}

func handleClient(conn net.Conn) {
	totalBytes, err := common.ReadAirdispatchMessage(conn)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Error reading in the message.")
		return
	}

	downloadedMessage := &airdispatch.SignedMessage{}
	err = proto.Unmarshal(totalBytes[0:], downloadedMessage)
	if err != nil {
		fmt.Println(err)
		fmt.Println("The message is malformed!")
		return
	}

	if !common.VerifySignedMessage(downloadedMessage) {
		fmt.Println("Message is not signed properly. Discarding")
		return
	}
	
	messageType := downloadedMessage.MessageType
	theAddress := common.StringAddress(common.BytesToKey(downloadedMessage.SigningKey))

	switch *messageType {
		case common.ALERT_MESSAGE:
			fmt.Println("Received Alert")
			assigned := &airdispatch.Alert{}
			err := proto.Unmarshal(downloadedMessage.Payload, assigned)
			if (err != nil) { fmt.Println("Bad Payload."); return; }
			handleAlert(assigned, theAddress)
		case common.RETRIEVAL_MESSAGE:
			fmt.Println("Received Retrival Request")
			assigned := &airdispatch.RetrieveData{}
			err := proto.Unmarshal(downloadedMessage.Payload, assigned)
			if (err != nil) { fmt.Println("Bad Payload."); return; }
			handleRetrival(assigned, theAddress, conn)
		case common.SEND_REQUEST:
			fmt.Println("Received Request to Send Message")
			assigned := &airdispatch.SendMailRequest{}
			err := proto.Unmarshal(downloadedMessage.Payload, assigned)
			if (err != nil) { fmt.Println("Bad Payload."); return; }
			handleSendRequest(assigned, theAddress)
	}
}

func handleAlert(alert *airdispatch.Alert, fromAddr string) {
	toAddr := *alert.ToAddress
	theMessage := Mail{
		location: *alert.Location,
		from: fromAddr,
	}
	_, ok := mailboxes[toAddr]
	if !ok {
		mailboxes[toAddr] = make(Mailbox)
	}
	mailboxes[toAddr][*alert.MessageId] = theMessage
	fmt.Println(mailboxes)
}

func handleRetrival(retrieval *airdispatch.RetrieveData, toAddr string, conn net.Conn) {
	message, ok := storedMessages[*retrieval.MessageId]
	if !ok {
		conn.Write(common.CreateErrorMessage("no message for that id"))
		return
	}
	if !common.SliceContains(message.approved, toAddr) {
		conn.Write(common.CreateErrorMessage("not an approved sender"))
		return
	}
	conn.Write(common.CreatePrefixedMessage(message.data))
}

func handleSendRequest(request *airdispatch.SendMailRequest, fromAddr string) {
	var toAddress []string = request.ToAddress
	var theMail = request.StoredMessage
	mailData, _ := proto.Marshal(theMail)
	hash := hex.EncodeToString(common.HashSHA(mailData, nil))

	for _, v := range(toAddress) {
		loc := LookupLocation(v)
		SendAlert(loc, hash, v)
	}

	storeData := MailData {
		approved: toAddress,
		data: mailData,
	}

	storedMessages[hash] = storeData

	fmt.Println("Stored Messages: ", storedMessages)
}

func LookupLocation(toAddr string) string {
	for _, v := range(connectedTrackers) {
		address, _ := net.ResolveTCPAddr("tcp", v)

		conn, err := net.DialTCP("tcp", nil, address)
		if err != nil {
			fmt.Println(err)
			fmt.Println("Unable to connect to the tracking server.")
			continue
		}

		finalLocation, err := SendQuery(conn, toAddr)
		if err == nil {
			return finalLocation
		}
	}
	return ""
}

func SendQuery(conn net.Conn, addr string) (string, error) {
	defer conn.Close()

	newQuery := &airdispatch.AddressRequest {
		Address: &addr,
	}

	mesType := common.QUERY_MESSAGE
	queryData, _ := proto.Marshal(newQuery)
	newSignedMessage, _ := common.CreateSignedMessage(serverKey, queryData, mesType)
	signedData, _ := proto.Marshal(newSignedMessage)
	totalBytes := common.CreatePrefixedMessage(signedData)

	conn.Write(totalBytes)
	data, _ := common.ReadAirdispatchMessage(conn)
	
	newQueryResponse := &airdispatch.AddressResponse{}
	proto.Unmarshal(data, newQueryResponse)
	
	return *newQueryResponse.ServerLocation, nil
} 

func SendAlert(location string, message_id string, toAddr string) {
	address, _ := net.ResolveTCPAddr("tcp", location)

	conn, err := net.DialTCP("tcp", nil, address)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Unable to connect to the receiving server.")
		return
	}

	newAlert := &airdispatch.Alert {
		ToAddress: &toAddr,
		Location: &serverLocation,
		MessageId: &message_id,
	}
	alertData, _ := proto.Marshal(newAlert)
	newSignedMessage, _ := common.CreateSignedMessage(serverKey, alertData, common.ALERT_MESSAGE)
	totalData, _ := proto.Marshal(newSignedMessage)
	bytesToSend := common.CreatePrefixedMessage(totalData)

	conn.Write(bytesToSend)
	conn.Close()
}
