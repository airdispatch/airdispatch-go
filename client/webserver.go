package main

import (
	"github.com/hoisie/web"
	"os"
	"io"
)

var WORKING_DIRECTORY string

func main() {
	defineConstants()
	defineRoutes()
	web.Run("0.0.0.0:9999")
}

func defineConstants() {
	WORKING_DIRECTORY, _ = os.Getwd()
}

func defineRoutes() {
	// Homepage
	web.Get("/", appResponse)

	// Authentication
	web.Get("/login", blankResponse)
	web.Post("/login", blankResponse)
	web.Get("/logout", blankResponse)

	// Mail API
	web.Get("/message", blankResponse)
	web.Post("/message", blankResponse)
}

func blankResponse() string {
	return WORKING_DIRECTORY + "AD_BLANK_RESPONSE"
}

func writeHeaders(ctx *web.Context) {
}

func appResponse(ctx *web.Context) {
	writeFileToContext("static/index.html", ctx)
}

func writeFileToContext(filename string, ctx *web.Context) {
	file, err := os.Open(WORKING_DIRECTORY + "/" + filename)
	if err != nil {
		displayErrorPage(ctx, "Unable to Open: " + WORKING_DIRECTORY + "/" + filename)
		return
	}

	_, err = io.Copy(ctx, file)
	if err != io.EOF && err != nil {
		displayErrorPage(ctx, "Unable to Copy into Buffer. File: " + WORKING_DIRECTORY + "/" + filename)
		return
	}
}

func displayErrorPage(ctx *web.Context, error string) {
	ctx.WriteString("<!DOCTYPE html><html><head><title>Project Error</title></head>")
	ctx.WriteString("<body><h1>Application Error</h1>")
	ctx.WriteString("<p>" + error + "</p>")
	ctx.WriteString("</body></html>")
}
