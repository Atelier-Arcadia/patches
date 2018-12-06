package main

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/arcrose/patches/pkg/platform"

	"github.com/arcrose/patches/internal/clients"
	"github.com/arcrose/patches/internal/limit"
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
		fmt.Fprintf(os.Stderr, "Missing required parameter 'server-address'\n")
		return
	}

	if *platformName == "" {
		fmt.Fprintf(os.Stderr, "Missing required parameter 'platform'\n")
		return
	}

	if *vulnsAPI == "" {
		fmt.Fprintf(os.Stderr, "Missing required parameter 'vulnerability-api'")
		return
	}

	rateLimiter := limit.NewConstantRateLimiter(200 * time.Millisecond)
	server := clients.NewClairClient(*serverAddr, *serverPort, rateLimiter)

	chosenPlatform, found := platform.Translate(*platformName)
	if !found {
		fmt.Fprintf(os.Stderr, "Unsupported platform '%s'\n", *platformName)
		return
	}

	scanner, err := scanners.Lookup(chosenPlatform, map[string]interface{}{
		"compareFn": pack.VersionIsPrefix,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unsupported platform or invalid config: '%s'", err.Error())
		return
	}

	reportAPI := __reportVulnsToAPI(vulnsAPI)

	agent := scanners.Agent{
		VulnSource:    server,
		Platform:      chosenPlatform,
		ScanFrequency: *scanFreq * time.Minute,
		SystemScanner: scanner,
		Findings:      reportAPI,
	}

	agent.Run()
}

func usage() {
	out := flag.CommandLine.Output()
	supportedPlatformNames := strings.Join(platform.SuppportedPlatformNames(), ", ")
	supportedReporterNames := strings.Join(supportedReporterNames(), ", ")

	flag.PrintDefaults()
	fmt.Fprintf(
		out,
		"Supported platforms: %s\n",
		supportedPlatformNames)
	fmt.Fprintf(
		out,
		"Supported reporters: %s\n",
		supportedReporterNames)
}

func __reportVulnsToAPI(endpt string) chan<- vulnerability.Vulnerability {
	vulns := make(chan vulnerability.Vulnerability)

	return vulns
}
