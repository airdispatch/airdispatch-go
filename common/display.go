package common;

import (
	"airdispat.ch/airdispatch"
	"code.google.com/p/goprotobuf/proto"
)

// A simple message to output an Airdispatch Message to String
func PrintMessage(mail *airdispatch.Mail) string {
	output := ""
	output += ("---- Message from " + *mail.FromAddress + " ----\n")
	output += ("Encryption Type: " + *mail.Encryption + "\n") 

	mailData := &airdispatch.MailData{}
	proto.Unmarshal(mail.Data, mailData)

	for _, value := range(mailData.Payload) {
		output += ("### " + *value.TypeName + "\n")
		output += (string(value.Payload) + "\n")
	}

	output += ("---- END ----")

	return output
}
