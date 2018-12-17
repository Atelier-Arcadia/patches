package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	http.HandleFunc("/", serveOK)
	http.ListenAndServe(":9001", nil)
}

func serveOK(res http.ResponseWriter, req *http.Request) {
	body, _ := ioutil.ReadAll(req.Body)
	req.Body.Close()
	fmt.Printf("Got a vuln: %s\n", body)
	res.Write([]byte("Ok"))
}
