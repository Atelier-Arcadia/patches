package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/arcrose/patches/pkg/pack"
	"github.com/arcrose/patches/pkg/platform"
	"github.com/arcrose/patches/pkg/vulnerability"

	"github.com/arcrose/patches/internal/clients"
	"github.com/arcrose/patches/internal/limit"
	"github.com/arcrose/patches/internal/scanners"
)

// The amount of time to collect vulnerabilities found on the host for
// before sending them in a batch request.
var TIME_TO_BATCH_VULNS_BEFORE_SEND = 5 * time.Minute

func main() {
	flag.Usage = usage

	patchesServer := flag.String(
		"patches-server",
		"http://127.0.0.1:8080",
		"Address of the patches-server to use as a source of vulnerability information")
	platformName := flag.String(
		"platform",
		"",
		"Name of the platform the agent is running on")
	scanFreq := flag.Uint(
		"scan-frequency",
		720,
		"Frequency with which the agent will pull and scan for vulnerable packages in minutes")
	mozdefProxy := flag.String(
		"mozdef-proxy",
		"",
		"Address of the MozDef-Proxy to report vulnerabilities to")

	flag.Parse()

	if *patchesServer == "" {
		log.Errorf("Missing required parameter 'patches-server'")
		return
	}

	if *platformName == "" {
		log.Errorf("Missing required parameter 'platform'")
		return
	}

	if *mozdefProxy == "" {
		log.Errorf("Missing required parameter 'mozdef-proxy'")
		return
	}

	chosenPlatform, found := platform.Translate(*platformName)
	if !found {
		log.Errorf("Unsupported platform '%s'", *platformName)
		return
	}

	log.Infof("Starting scanner")

	rateLimiter := limit.ConstantRateLimiter(200 * time.Millisecond)
	server := clients.NewClairClient(*patchesServer, rateLimiter)

	scanner, err := scanners.Lookup(chosenPlatform, map[string]interface{}{
		"compareFn": pack.VersionCompareFunc(pack.VersionIsPrefix),
	})
	if err != nil {
		log.Errorf("Unsupported platform or invalid config: '%s'", err.Error())
		return
	}

	// This code should die sometime soon.
	// START
	killReporter := make(chan bool, 2)
	confirmReporterKilled := make(chan bool, 2)
	reportToAPI, errs := __reportVulnsToAPI(
		*mozdefProxy,
		TIME_TO_BATCH_VULNS_BEFORE_SEND,
		killReporter,
		confirmReporterKilled)
	defer func() {
		killReporter <- true
		killReporter <- true
		<-confirmReporterKilled
		<-confirmReporterKilled
	}()
	go func() {
	errorlogger:
		for {
			select {
			case err := <-errs:
				log.Error(err)

			case <-killReporter:
				confirmReporterKilled <- true
				break errorlogger
			}
		}
	}()
	// This code should die sometime soon.
	// END

	agent := scanners.Agent{
		VulnSource:    server,
		Platform:      chosenPlatform,
		ScanFrequency: time.Duration(*scanFreq) * time.Minute,
		SystemScanner: scanner,
		Findings:      reportToAPI,
	}

	agent.Run()
}

func usage() {
	out := flag.CommandLine.Output()
	supportedPlatformNames := strings.Join(platform.SuppportedPlatformNames(), "\n")

	flag.PrintDefaults()
	fmt.Fprintf(
		out,
		"\nSupported platforms:\n%s\n",
		supportedPlatformNames)
}

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
