package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
)

var Random = rand.Reader

// Quickly Generate an Address Checksum
func generateChecksum(address []byte) []byte {
	return HashSHA(HashSHA(address))[0:4]
}

// Hex decode an Address then verify that it is correct, then
// pass it to the byte verification function
func VerifyStringAddress(address string) bool {
	byteAddress, err := hex.DecodeString(string(address))
	if err != nil {
		return false
	}

	return verifyAddress(byteAddress)
}

// Verify an Airdispatch Address from Bytes by comparing the checksum
// to the one provided
func verifyAddress(address []byte) bool {
	location := len(address) - 4
	checksum := address[location:]
	rest := address[:location]
	return bytes.Equal(generateChecksum(rest), checksum)
}

// This function pads a bytestring to the correct length
// assuming that the bytestring is in big-endian format
//
// THIS FUNCTION HAS NOTHING TO DO WITH AES. IT IS ONLY USED FOR
// STORAGE OF SIGNING KEYS.
func padding(byteArray []byte, length int) []byte {
	if len(byteArray) > length {
		return nil
	} else if len(byteArray) == length {
		return byteArray
	}
	diff := length - len(byteArray)
	pad := make([]byte, diff)
	return bytes.Join([][]byte{pad, byteArray}, nil)
}
