package main

import (
	"fmt"
	"airdispat.ch/tracker/framework"
	"airdispat.ch/common"
	"flag"
)

var port = flag.String("port", "2048", "select the port on which to run the tracking server")

var storedAddresses map[string]*framework.TrackerRecord

func main() {
	flag.Parse()

	// Initialize the Database of Addresses
	storedAddresses = make(map[string]*framework.TrackerRecord)

	theKey, err := common.CreateKey()
	if err != nil {
		fmt.Println("Unable to Create Tracker Key")
		return
	}

	theTracker := &framework.Tracker {
		Key: theKey,
		Delegate: &myTracker{},
	}
	theTracker.StartServer(*port)
}

type myTracker struct {
	framework.BasicTracker
}

func (myTracker) SaveTrackerRecord(data *framework.TrackerRecord) {
	// Store the RegisterdAddress in the Database
	storedAddresses[data.Address] = data
}

func (myTracker) GetRecordByUsername(username string) *framework.TrackerRecord {
	// TODO: We should really use a database, this is _very_ inefficient.
	// Lookup the Address (by username) in the Database
	for _, v := range(storedAddresses) {
		if v.Username == username {
			return v
		}
	}
	return nil
}

func (myTracker) GetRecordByAddress(address string) *framework.TrackerRecord {
	// Lookup the Address (by address) in the Database
	info, _ := storedAddresses[address]
	return info
}
