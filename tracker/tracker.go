package main

import (
	"net"
	"fmt"
	"bytes"
	"encoding/binary"
	"code.google.com/p/goprotobuf/proto"
	"airdispat.ch/airdispatch"
	"airdispat.ch/common"
)

func main() {

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
	var length int16

	// Make Sure to Get the Full Message
	// First Two Bytes Contain the Length

	for {
		data := make([]byte, 256)
		_, err := conn.Read(data)
		if err != nil {
			fmt.Println(err)
			fmt.Println("Unable to read from client!")
		}

		if !started {
			binary.Read(bytes.NewBuffer(data[0:2]), binary.BigEndian, &length)
			started = true
			fmt.Println(length)
		}	

		buf.Write(data)

		if int16(buf.Len()) >= length {
			break
		}
	}

	// Finished Downloading Message. Now, design and figure out what type it is.
	totalBytes := buf.Bytes()
	fmt.Println(totalBytes[2:length + 2])
	
	downloadedMessage := &airdispatch.SignedMessage{}
	err := proto.Unmarshal(totalBytes[2:length + 2], downloadedMessage)
	if err != nil {
		fmt.Println(err)
		fmt.Println("The message is malformed!")
	}
	fmt.Println(downloadedMessage)
}

func verifySigned(mes *airdispatch.SignedMessage) (bool) {
	return true
}
