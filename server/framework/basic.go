package framework

import (
	"fmt"
)

type BasicServer struct{
	ServerDelegate
}

func (BasicServer) HandleError(err *ServerError) {
	fmt.Println("Error Occurred At: " + err.Location + " - " + err.Error.Error())
	// os.Exit(1)
}

func (BasicServer) AllowSendConnection(fromAddr string) bool {
	return true
}

func (BasicServer) LogMessage(toLog string) {
	fmt.Println(toLog)
}