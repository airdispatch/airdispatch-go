package framework

import (
	"fmt"
)

type BasicTracker struct{
	TrackerDelegate
}

func (BasicTracker) HandleError(err *TrackerError) {
	fmt.Println("Error Occurred At: " + err.Location + " - " + err.Error.Error())
	// os.Exit(1)
}

func (BasicTracker) AllowConnection(fromAddr string) bool {
	return true
}

func (BasicTracker) LogMessage(toLog string) {
	fmt.Println(toLog)
}