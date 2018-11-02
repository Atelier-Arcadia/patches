package main

import (
	"fmt"

	"github.com/zsck/patches/internal/scanners/clair"
)

func main() {
	clairAPI := clair.ClairAPIv1{
		BaseURL: "http://127.0.0.1:6060",
	}
	summaries, done, errs := clair.GetVulnSummaries(clairAPI, clair.Debian8)

readall:
	for {
		select {
		case err := <-errs:
			fmt.Printf("Got an error: '%s'\n", err.Error())
		case <-done:
			break readall
		case v := <-summaries:
			fmt.Printf("Got vulnerability: %s\n", v.Name)
		}
	}

	fmt.Println("Done")
}
