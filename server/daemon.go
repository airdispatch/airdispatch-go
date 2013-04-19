package main

import (
	"fmt"
	"net"
	"flag"
	"airdispat.ch/common"
	"airdispat.ch/airdispatch"
	"code.google.com/p/goprotobuf/proto"
)

var port = flag.String("port", "2048", "select the port on which to run the mail server")

var mailboxes map[string] []Mail

type Mail struct {
	from string
	location string
	message_id string
}

func main() {
	flag.Parse()

	mailboxes = make(map[string][]Mail)

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
	}
}

func handleAlert(alert *airdispatch.Alert, fromAddr string) {
	toAddr := *alert.ToAddress
	theMessage := Mail{
		location: *alert.Location,
		message_id: *alert.MessageId,
		from: fromAddr,
	}
	_, ok := mailboxes[toAddr]
	if !ok {
		mailboxes[toAddr] = make([]Mail, 0)
	}
	mailboxes[toAddr] = append(mailboxes[toAddr], theMessage)
	fmt.Println(mailboxes)
}
