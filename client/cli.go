// +build !heroku

package main

import (
	"net"
	"fmt"
	"code.google.com/p/goprotobuf/proto"
	"airdispat.ch/airdispatch"
	"airdispat.ch/common"
	"flag"
	"encoding/hex"
	"crypto/ecdsa"
)

var mode string //= flag.String("mode", "", "select the mode of the tracker connection, 'query' or 'register'")
var lookup string //= flag.String("address", "", "specify the address you would like to look up")
var remote string //= flag.String("tracker", "localhost:2048", "specify the server and port on which to connect")
var myAddress string
var key *ecdsa.PrivateKey

const REGISTRATION = "registration"
const QUERY = "query"
const ALERT = "alert"

func main() {
	flag.Parse()
	fmt.Print("Mode: ")
	fmt.Scanln(&mode)
	fmt.Print("Remote Server: ")
	fmt.Scanln(&remote)
	fmt.Print("Send or Query Address: ")
	fmt.Scanln(&lookup)
	address, _ := net.ResolveTCPAddr("tcp", remote)

	conn, err := net.DialTCP("tcp", nil, address)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Cannot connect to server.")
		return
	}

	switch {
		case mode == REGISTRATION:
			fmt.Println("Sending a Registration Request")
			sendRegistration(conn, true)
		case mode == QUERY:
			if lookup == "" {
				fmt.Println("You must supply an address for a lookup query.")
				return
			}
			fmt.Println("Sending a Query for " + lookup)
			sendQuery(conn, lookup, false)
		case mode == ALERT:
			if lookup == "" {
				fmt.Println("You must supply an address for an alert.")
				return
			}
			fmt.Println("Sending a Mail Alert for " + lookup)
			sendAlert(conn, lookup)
		case mode == "send":
			sendRegistration(conn, false)
			fmt.Println("Finished Ad Reg")
			sendMail(conn, lookup, true)
		case true:
			fmt.Println("You must specify a mode to run this in. -mode registration or -mode query")
	}
	conn.Close()
}

func sendRegistration(conn net.Conn, doAnything bool) {
	key, _ = common.CreateKey()
	createdAddress := common.StringAddress(&key.PublicKey)
	myAddress = createdAddress
	if !doAnything { return }
	fmt.Println("Created the Address:", createdAddress)
	mesType := common.REGISTRATION_MESSAGE
	byteKey := common.KeyToBytes(&key.PublicKey)
	var location string
	fmt.Print("Location to Send Messages To: ")
	fmt.Scanln(&location)
	
	newRegistration := &airdispatch.AddressRegistration{
		Address: &createdAddress,
		PublicKey: byteKey,
		Location: &location, 
	}

	regData, _ := proto.Marshal(newRegistration)
	newSignedMessage, _ := common.CreateSignedMessage(key, regData, mesType)
	data, _ := proto.Marshal(newSignedMessage)
	toSend := common.CreatePrefixedMessage(data)
	conn.Write(toSend)

	var check string
	fmt.Print("Want to check for mail? ")
	fmt.Scanln(&check)
	if check == "n" { return }

}

func sendQuery(conn net.Conn, addr string, keepGoing bool) {
	defer conn.Close()

	key, _ := common.CreateKey()

	newQuery := &airdispatch.AddressRequest {
		Address: &addr,
	}

	mesType := common.QUERY_MESSAGE
	queryData, _ := proto.Marshal(newQuery)
	newSignedMessage, _ := common.CreateSignedMessage(key, queryData, mesType)
	signedData, _ := proto.Marshal(newSignedMessage)
	totalBytes := common.CreatePrefixedMessage(signedData)

	conn.Write(totalBytes)
	data, _ := common.ReadAirdispatchMessage(conn)
	
	newQueryResponse := &airdispatch.AddressResponse{}
	proto.Unmarshal(data, newQueryResponse)
	
	fmt.Println("Received Location for Address:", *newQueryResponse.ServerLocation)
}

func sendMail(conn net.Conn, addr string, keepGoing bool) {
	if keepGoing {

		var serverLoc string
		fmt.Print("Server Location: ")
		fmt.Scanln(&serverLoc)
	
	serverAd, _ := net.ResolveTCPAddr("tcp", serverLoc)

	server, err := net.DialTCP("tcp", nil, serverAd)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Cannot connect to server.")
		return
	}

	fmt.Println("Time to define the data!")
	var enc = "none"
	mail := &airdispatch.Mail { FromAddress: &myAddress, Encryption: &enc }
	mailData := &airdispatch.MailData{}
	allTypes := make([]*airdispatch.MailData_DataType, 0) 

	for {
		var typename string
		var data string
		fmt.Print("Data Type (or done to stop): ")
		fmt.Scanln(&typename)
		if typename == "done" { break }
		fmt.Print("Data: ")
		fmt.Scanln(&data)
		newData := &airdispatch.MailData_DataType {
			TypeName: &typename,
			Payload: []byte(data),
			Encryption: &enc,
		}
		allTypes = append(allTypes, newData)
	}

	mailData.Payload = allTypes
	theMail, _ := proto.Marshal(mailData)
	mail.Data = theMail

	sendRequest := &airdispatch.SendMailRequest {
		ToAddress: []string{lookup},
		StoredMessage: mail,
	}
	sendBytes, _ := proto.Marshal(sendRequest)
	signedMes, _ := common.CreateSignedMessage(key, sendBytes, "SEN")

	toSend, _ := proto.Marshal(signedMes)

	server.Write(common.CreatePrefixedMessage(toSend))
	
	}
} 


func sendAlert(conn net.Conn, addr string) {
	defer conn.Close()

	key, _ := common.CreateKey()
	hash := hex.EncodeToString(common.HashSHA(nil, []byte("hello")))
	location := "google.com"

	newAlert := &airdispatch.Alert {
		ToAddress: &addr,
		Location: &location,
		MessageId: &hash,
	}

	alertData, _ := proto.Marshal(newAlert)
	newSignedMessage, _ := common.CreateSignedMessage(key, alertData, common.ALERT_MESSAGE)
	signedData, _ := proto.Marshal(newSignedMessage)
	totalBytes := common.CreatePrefixedMessage(signedData)
	conn.Write(totalBytes)
}
