package main

import (
	"net/http"
)

func main() {
	http.HandleFunc("/", serveOK)
	http.ListenAndServe(":9001", nil)
}

func serveOK(res http.ResponseWriter, req *http.Request) {
	res.Write([]byte("Ok"))
}
