// The wire package contains all of the Protocol Buffers
// source files and compiled go files. Additionally, it contains
// certain important constants for AirDispatch servers.
package wire

import (
// "code.google.com/p/goprotobuf/proto"
)

var Prefix []byte = []byte("AD")

// The constants represent the three-letter codes that denote each type of
// Airdispatch message. The names of each constant should make the message
// that they each represent self-apparent.
const (
	MessageDescriptionCode = "MDE"
	TranferMessageCode     = "XFM"
	TranferMessageListCode = "XFL"
	MailCode               = "MAI"
	DataCode               = "DAT"
	ErrorCode              = "ERR"
)
