package main

import (
	"github.com/hoisie/web"
)

func main() {
	defineRoutes()
    web.Run("0.0.0.0:9999")
}

func defineRoutes() {
	// Homepage
	web.Get("/", blankResponse)

	// Application Layer
	web.Get("/app", blankResponse)

	// Authentication
	web.Get("/login", blankResponse)
	web.Post("/login", blankResponse)
	web.Get("/logout", blankResponse)

	// Mail API
	web.Get("/message/list", blankResponse)
	web.Post("/message/send", blankResponse)
}

func blankResponse() string {
	return "AD_BLANK_RESPONSE"
}
