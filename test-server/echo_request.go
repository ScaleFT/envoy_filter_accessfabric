package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
)

func index(w http.ResponseWriter, r *http.Request) {
	resp, err := httputil.DumpRequest(r, true)
	if err != nil {
		fmt.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	fmt.Printf("%s\n", resp)
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(resp)
	if err != nil {
		fmt.Println(err.Error())
	}
}

func main() {
	http.HandleFunc("/", index)              // set router
	err := http.ListenAndServe(":8082", nil) // set listen port
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
