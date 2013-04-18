package main

import (
	"io"
	"net"
	"fmt"
	"bytes"
	"encoding/binary"
	"code.google.com/p/goprotobuf/proto"
	"airdispat.ch/airdispatch"
	"airdispat.ch/common"
)

var storedAddresses map[string]RegisteredAddress

type RegisteredAddress struct {
	public_key []byte
	location string
	username string
}

func main() {

	storedAddresses = make(map[string]RegisteredAddress)

	service := ":2048"
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
	defer conn.Close()

	buf := &bytes.Buffer{}
	started := false	
	lengthBuffer := make([]byte, 2)
	var length int16

	// Make Sure to Get the Full Message
	// First Two Bytes Contain the Length
	fmt.Println("--- STARTING READ ---")

	for {
		if !started {
			io.ReadFull(conn, lengthBuffer)
			binary.Read(bytes.NewBuffer(lengthBuffer[0:]), binary.BigEndian, &length)
			started = true
			fmt.Println(length)
		}

		data := make([]byte, 256)
		n, err := io.ReadFull(conn, data)
		fmt.Println("Read:", data)
		if err != nil && n > len(data) {
			fmt.Println(err)
			fmt.Println("Unable to read from client!")
			return
		}

		buf.Write(data)

		if int16(buf.Len()) >= length {
			break
		}
	}

	// Finished Downloading Message. Now, design and figure out what type it is.
	totalBytes := buf.Bytes()
	fmt.Println(totalBytes[0:length])
	
	downloadedMessage := &airdispatch.SignedMessage{}
	err := proto.Unmarshal(totalBytes[0:length], downloadedMessage)
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
		case "reg":
			fmt.Println("Received Registration")
			assigned := &airdispatch.AddressRegistration{}
			err := proto.Unmarshal(downloadedMessage.Payload, assigned)
			if (err != nil) { fmt.Println("Bad Payload."); return; }
			handleRegistration(theAddress, assigned) 
		case "que":
			fmt.Println("Received Query")
			assigned := &airdispatch.AddressRequest{}
			err := proto.Unmarshal(downloadedMessage.Payload, assigned)
			if (err != nil) { fmt.Println("Bad Payload."); return; }
			handleQuery(theAddress, assigned, conn) 
	}
}

func handleRegistration(theAddress string, reg *airdispatch.AddressRegistration) {
	data := RegisteredAddress {
		public_key: reg.PublicKey,
		location: *reg.Location,
		username: "",
	}
	storedAddresses[theAddress] = data
	fmt.Println(storedAddresses)
}

func handleQuery(theAddress string, req *airdispatch.AddressRequest, conn net.Conn) {
}
