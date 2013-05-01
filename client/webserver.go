// +build heroku
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
	web.Run("0.0.0.0:" + os.Getenv("PORT"))
}

func defineConstants() {
	temp_dir = os.Getenv("WORK_DIR")
	if temp_dir == "" {
		temp_dir, _ = os.Getwd()
	}
	WORKING_DIRECTORY = temp_dir
}

func defineRoutes() {
	// Homepage
	web.Get("/", appResponse)

	// Authentication
	web.Post("/login", loginResponse)
	web.Get("/logout", logoutResponse)

	// Mail API
	web.Get("/message", messageListResponse)
	web.Post("/message", messageSendResponse)
}

func blankResponse() string {
	return WORKING_DIRECTORY
}

func writeHeaders(ctx *web.Context) {
}

func messageListResponse(ctx *web.Context) {
	writeFileToContext("static/sample.json", ctx)
}

func messageSendResponse(ctx *web.Context) {
	ctx.WriteString("OK")
}

func loginResponse(ctx *web.Context) {
	ctx.WriteString("OK")
}

func logoutResponse(ctx *web.Context) {
	ctx.WriteString("OK")
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
