package common

import (
	"airdispat.ch/airdispatch"
	"code.google.com/p/goprotobuf/proto"
)

// A simple message to output an Airdispatch Message to String
func PrintMessage(mail *airdispatch.Mail, key *ADKey) string {
	output := ""
	output += ("---- Message from " + *mail.FromAddress + " ----\n")
	output += ("Encryption Type: " + *mail.Encryption + "\n")

	mailData := &airdispatch.MailData{}
	toUnmarshal := mail.Data

	if *mail.Encryption == ADEncryptionRSA {
		data, err := key.DecryptPayload(mail.Data)

		if err != nil {
			output += ("---- COULDN'T DECRYPT MESSAGE ----")
			return output
		}

		toUnmarshal = data
	}

	proto.Unmarshal(toUnmarshal, mailData)

	for _, value := range mailData.Payload {
		output += ("### " + *value.TypeName + "\n")
		output += (string(value.Payload) + "\n")
	}

	output += ("---- END ----")

	return output
}
