package framework

import (
	"fmt"
	"os"
)

type BasicServer struct{
	ServerHandler
}

func (BasicServer) HandleError(err ServerError) {
	fmt.Println(err.Error)
	os.Exit(1)
}

func (BasicServer) AllowConnection(fromAddr string) bool {
	return true
}