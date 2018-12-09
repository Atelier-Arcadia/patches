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

func main() {
	flag.Usage = usage

	serverAddr := flag.String(
		"server-address",
		"",
		"Address of the patches-server to use as a source of vulnerability information")
	serverPort := flag.Uint(
		"server-port",
		443,
		"Port of the patches-server to connect to")
	platformName := flag.String(
		"platform",
		"",
		"Name of the platform the agent is running on")
	scanFreq := flag.Uint(
		"scan-frequency",
		720,
		"Frequency with which the agent will pull and scan for vulnerable packages in minutes")
	vulnsAPI := flag.String(
		"vulnerability-api",
		"",
		"Full URL for a REST API endpoint that vulnerabilities found on the host will be sent to")

	flag.Parse()

	if *serverAddr == "" {
		log.Errorf("Missing required parameter 'server-address'")
		return
	}

	if *platformName == "" {
		log.Errorf("Missing required parameter 'platform'")
		return
	}

	if *vulnsAPI == "" {
		log.Errorf("Missing required parameter 'vulnerability-api'")
		return
	}

	rateLimiter := limit.ConstantRateLimiter(200 * time.Millisecond)
	server := clients.NewClairClient(*serverAddr, uint16(*serverPort), rateLimiter)

	chosenPlatform, found := platform.Translate(*platformName)
	if !found {
		log.Errorf("Unsupported platform '%s'", *platformName)
		return
	}

	scanner, err := scanners.Lookup(chosenPlatform, map[string]interface{}{
		"compareFn": pack.VersionIsPrefix,
	})
	if err != nil {
		log.Errorf("Unsupported platform or invalid config: '%s'", err.Error())
		return
	}

	// This code should die sometime soon.
	// START
	killReporter := make(chan bool, 2)
	confirmReporterKilled := make(chan bool, 2)
	reportToAPI, errs := __reportVulnsToAPI(*vulnsAPI, killReporter, confirmReporterKilled)
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

func __reportVulnsToAPI(
	endpt string,
	terminate <-chan bool,
	confirm chan<- bool,
) (
	chan<- vulnerability.Vulnerability,
	<-chan error,
) {
	vulns := make(chan vulnerability.Vulnerability)
	errs := make(chan error)

	go func() {
	reporting:
		for {
			select {
			case vuln := <-vulns:
				go __report(endpt, vuln, errs)

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
	vuln vulnerability.Vulnerability,
	errs chan<- error,
) {
	encoded, err := json.Marshal(vuln)
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
