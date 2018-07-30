// Copyright (c) 2016 BLOCKO INC.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Printf("Error reading body: %v", err)
			http.Error(w, "can't read body", http.StatusBadRequest)
			return
		}
		decoded, err := hex.DecodeString("616263")
		if err != nil {
			fmt.Println("Decode failed")
		}
		fmt.Println("Encoded Recieved: ", string(body))
		fmt.Println("Encoded Recieved: ", string(decoded))

		type Message struct {
			UDEvent string
			Data    *json.RawMessage
		}
		var um Message
		err = json.Unmarshal(body, &um)
		if err != nil {
			fmt.Println("Unmarshal Error", err)
		}
		/*
			Databinary, err := hex.DecodeString(um.Data)
			um.Data = string(Databinary)
		*/
		fmt.Printf("Unmarshal : %v\n", um)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))

}
