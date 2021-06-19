package main

import (
	"io"
	"log"
	"net/http"
	"os"
)

func main() {

	// Login to get token
	res, err := http.Get("http://localhost:8080/login")
	if err != nil {
		log.Fatalf("Error getting response; %v", err)
	}

	// Read the token out of the response body
	// buf := new(bytes.Buffer)
	// io.Copy(buf, res.Body)
	// res.Body.Close()
	// tokenString := strings.TrimSpace(buf.String())

	// load jwt from cookie
	jwtToken := res.Cookies()[0].Value

	clientReq, err := http.NewRequest("GET", "http://localhost:8080/products", nil)

	// add jwt token to Authorization Header
	clientReq.Header.Add("Authorization", "Bearer "+jwtToken)

	res, err = http.DefaultClient.Do(clientReq)

	if err != nil {
		panic(err)
	}

	io.Copy(os.Stdout, res.Body)

}
