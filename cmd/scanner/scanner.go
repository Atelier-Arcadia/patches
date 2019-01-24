package main

import (
	"flag"
	"fmt"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/Atelier-Arcadia/patches/pkg/pack"
	"github.com/Atelier-Arcadia/patches/pkg/platform"

	"github.com/Atelier-Arcadia/patches/internal/clients"
	"github.com/Atelier-Arcadia/patches/internal/limit"
	"github.com/Atelier-Arcadia/patches/internal/scanners"
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
