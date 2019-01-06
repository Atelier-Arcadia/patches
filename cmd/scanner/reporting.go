package main

import (
  "bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	log "github.com/Sirupsen/logrus"

  "github.com/arcrose/patches/pkg/vulnerability"
)

//  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //
//////////////////////////////////////////////////////////////////////
// At some point we'll want to abstract this kind of functionality  //
// out so that users can opt into reporting vulnerabilities to      //
// other places.                                                    //
//////////////////////////////////////////////////////////////////////
//  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //  //

// __reportVulnsToAPI runs a goroutine that will read vulnerabilities
// found on the host, batch them into a list and send them periodically.
func __reportVulnsToAPI(
	endpt string,
	sendEvery time.Duration,
	terminate <-chan bool,
	confirm chan<- bool,
) (
	chan<- vulnerability.Vulnerability,
	<-chan error,
) {
	vulns := make(chan vulnerability.Vulnerability)
	errs := make(chan error)

	go func() {
		batch := make([]vulnerability.Vulnerability, 32)
		batchIndex := 0
		maxBatchIndex := 32

		lastSentVulns := time.Now()

	reporting:
		for {
			timeLeftBeforeSend := time.Until(lastSentVulns.Add(sendEvery))

			select {
			case vuln := <-vulns:
				if batchIndex >= maxBatchIndex {
					batch = append(batch, vuln)
					batchIndex++
					maxBatchIndex++
				} else {
					batch[batchIndex] = vuln
					batchIndex++
				}

			case <-time.After(timeLeftBeforeSend):
				lastSentVulns = time.Now()
				if batchIndex > 0 {
					log.Infof("Reporting %d found vulnerabilities", batchIndex)
					vulns := make([]vulnerability.Vulnerability, batchIndex)
					copy(vulns, batch[:batchIndex])
					go __report(endpt, vulns, errs)
					batchIndex = 0
				}

			case <-terminate:
				confirm <- true
				break reporting
			}
		}
	}()

	return vulns, errs
}

func __report(
	endpt string,
	vulns []vulnerability.Vulnerability,
	errs chan<- error,
) {
	encoded, err := json.Marshal(struct {
		Vulnerabilities []vulnerability.Vulnerability `json:"vulnerabilities"`
	}{vulns})
	if err != nil {
		errs <- err
		return
	}

	resp, err := http.Post(endpt, "application/json", bytes.NewReader(encoded))
	if err != nil {
		errs <- err
		return
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf(
			"Vulnerability reporter got status code %d from API",
			resp.StatusCode)
		errs <- err
		return
	}
}

