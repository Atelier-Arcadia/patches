package clair

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	log "github.com/Sirupsen/logrus"

	"github.com/arcrose/patches/pkg/done"
	"github.com/arcrose/patches/pkg/pack"
	"github.com/arcrose/patches/pkg/platform"
	"github.com/arcrose/patches/pkg/vulnerability"

	"github.com/arcrose/patches/internal/limit"
)

const vulnSummariesWithoutPageEndptFmt string = "/v1/namespaces/%s/vulnerabilities?limit=999"
const vulnSummariesWithPageEndptFmt string = "/v1/namespaces/%s/vulnerabilities?page=%s&limit=999"
const vulnDescriptionEndptFmt string = "/v1/namespaces/%s/vulnerabilities/%s?fixedIn"

// ClairAPIv1 contains the configuration required to communicate with V1 of the Clair API.
type ClairAPIv1 struct {
	BaseURL string
}

// Stream implements the Source
type Stream struct {
	config ClairAPIv1
	block  limit.RateLimiter
}

type summary struct {
	Name string `json:"Name"`
}

type fix struct {
	Name    string `json:"Name"`
	Version string `json:"Version"`
}

type description struct {
	Name     string `json:"Name"`
	Link     string `json:"Link"`
	Severity string `json:"Severity"`
	FixedIn  []fix  `json:"FixedIn"`
}

type descriptionResponse struct {
	Vulnerability description `json:"Vulnerability"`
}

type summaryResponse struct {
	Vulnerabilities []summary `json:"Vulnerabilities"`
	NextPage        *string   `json:"NextPage"`
}

type message struct {
	Message string `json:"Message"`
}

type errorResponse struct {
	Error message `json:"Error"`
}

// NewStream constructs a new stream from which vulnerabilitiies affecting
// packages for a particular platform can be streamed.
func NewStream(config ClairAPIv1, limiter limit.RateLimiter) Stream {
	return Stream{
		config,
		limiter,
	}
}

func toVulnerability(desc description, pform platform.Platform) vulnerability.Vulnerability {
	vuln := vulnerability.Vulnerability{
		Name:                 desc.Name,
		AffectedPackageName:  desc.FixedIn[0].Name,
		AffectedPlatformName: pform.String(),
		DetailsHref:          desc.Link,
		SeverityRating:       toSeverity(desc.Severity),
		FixedInPackages:      make([]pack.Package, len(desc.FixedIn)),
	}

	for i, fixPkg := range desc.FixedIn {
		vuln.FixedInPackages[i] = toPackage(fixPkg)
	}

	return vuln
}

func toSeverity(sev string) vulnerability.Severity {
	switch sev {
	case "Unknown":
		return vulnerability.SeverityUnknown

	case "Negligible":
		return vulnerability.SeverityNegligible

	case "Low":
		return vulnerability.SeverityLow

	case "Medium":
		return vulnerability.SeverityMedium

	case "High":
		return vulnerability.SeverityHigh

	case "Critical":
		return vulnerability.SeverityCritical

	case "Defcon1":
		return vulnerability.SeverityUrgent

	default:
		return vulnerability.SeverityUnknown
	}
}

func toPackage(f fix) pack.Package {
	return pack.Package{
		Name:    f.Name,
		Version: f.Version,
	}
}

func translateName(pform platform.Platform) string {
	translations := map[platform.Platform]string{
		platform.CentOS5:        "centos:5",
		platform.CentOS6:        "centos:6",
		platform.CentOS7:        "centos:7",
		platform.Debian8:        "debian:8",
		platform.Debian9:        "debian:9",
		platform.Debian10:       "debian:10",
		platform.DebianUnstable: "debian:unstable",
		platform.Alpine3_3:      "alpine:v3.3",
		platform.Alpine3_4:      "alpine:v3.4",
		platform.Alpine3_5:      "alpine:v3.5",
		platform.Alpine3_6:      "alpine:v3.6",
		platform.Alpine3_7:      "alpine:v3.7",
		platform.Alpine3_8:      "alpine:v3.8",
		platform.Oracle5:        "oracle:5",
		platform.Oracle6:        "oracle:6",
		platform.Oracle7:        "oracle:7",
		platform.Ubuntu12_04:    "ubuntu:12.04",
		platform.Ubuntu12_10:    "ubuntu:12.10",
		platform.Ubuntu13_04:    "ubuntu:13.04",
		platform.Ubuntu13_10:    "ubuntu:13.10",
		platform.Ubuntu14_04:    "ubuntu:14.04",
		platform.Ubuntu14_10:    "ubuntu:14.10",
		platform.Ubuntu15_04:    "ubuntu:15.04",
		platform.Ubuntu15_10:    "ubuntu:15.10",
		platform.Ubuntu16_04:    "ubuntu:16.04",
		platform.Ubuntu16_10:    "ubuntu:16.10",
		platform.Ubuntu17_04:    "ubuntu:17.04",
		platform.Ubuntu17_10:    "ubuntu:17.10",
		platform.Ubuntu18_04:    "ubuntu:18.04",
	}

	name, _ := translations[pform]
	return name
}

// summarizeVulnerabilities runs a goroutine that streams out summaries of
// vulnerabilities affecting a platform as described by the Clair v1 API.
func summarizeVulnerabilities(
	config ClairAPIv1,
	block limit.RateLimiter,
	pform platform.Platform,
) (<-chan summary, <-chan done.Done, <-chan error) {
	summaries := make(chan summary)
	finished := make(chan done.Done)
	errs := make(chan error)

	go __collect(config, block, pform, summaries, finished, errs)
	return summaries, finished, errs
}

// describeVulnerability runs a goroutine that requests detailed infomration
// about a vulnerability affecting a platform from the Clair v1 API.
func describeVulnerability(
	config ClairAPIv1,
	block limit.RateLimiter,
	vulnName string,
	pform platform.Platform,
) (<-chan description, <-chan done.Done, <-chan error) {
	descriptions := make(chan description)
	finished := make(chan done.Done)
	errs := make(chan error)

	go __describe(config, block, vulnName, pform, descriptions, finished, errs)
	return descriptions, finished, errs
}

// __collect makes requests to the Clair API until it has enumerated all of the
// pages containing names of vulnerabilities for the platform requested.
func __collect(
	cfg ClairAPIv1,
	block limit.RateLimiter,
	pform platform.Platform,
	summaries chan<- summary,
	finished chan<- done.Done,
	errs chan<- error,
) {
	base, err := url.Parse(cfg.BaseURL)
	if err != nil {
		log.Errorf("Error encountered in __collect: '%s'", err.Error())
		errs <- err
		finished <- done.Done{}
		return
	}

	ext := fmt.Sprintf(vulnSummariesWithoutPageEndptFmt, pform)
	nextPage := __getSummaries(base, ext, summaries, errs)
	for nextPage != "" {
		<-block()
		ext = fmt.Sprintf(vulnSummariesWithPageEndptFmt, pform, nextPage)
		nextPage = __getSummaries(base, ext, summaries, errs)
	}
	finished <- done.Done{}
}

// __describe performs a request to the Clair API to get detailed information
// about one specific vulnerability.
func __describe(
	cfg ClairAPIv1,
	block limit.RateLimiter,
	vulnName string,
	pform platform.Platform,
	descriptions chan<- description,
	finished chan<- done.Done,
	errs chan<- error,
) {
	base, err := url.Parse(cfg.BaseURL)
	if err != nil {
		log.Errorf("Encountered an error in __describe: '%s'", err.Error())
		errs <- err
		finished <- done.Done{}
		return
	}

	name := strings.Split(vulnName, " ")[0]
	ext := fmt.Sprintf(vulnDescriptionEndptFmt, pform, name)
	endpt, _ := url.Parse(ext)
	toReq := base.ResolveReference(endpt)

	response, err := http.Get(toReq.String())
	if err != nil {
		log.Errorf("Encountered an error in __describe: '%s'", err.Error())
		errs <- err
		finished <- done.Done{}
		return
	}
	defer response.Body.Close()

	respJSON := map[string]interface{}{}
	decoder := json.NewDecoder(response.Body)
	decodeErr := decoder.Decode(&respJSON)
	if decodeErr != nil {
		log.Errorf("Encountered an error in __describe: '%s'", decodeErr.Error())
		errs <- decodeErr
		finished <- done.Done{}
		return
	}

	if errMsg, convertErr := __toErrorResponse(respJSON); convertErr == nil {
		log.Errorf("Clair responded with an error: '%s'", errMsg.Error.Message)
		errs <- errors.New(errMsg.Error.Message)
		finished <- done.Done{}
		return
	}
	if description, convertErr := __toDescriptionResponse(respJSON); convertErr == nil {
		log.Debugf("Got vulnerability details for '%s'", vulnName)
		descriptions <- description.Vulnerability
	} else {
		//log.Errorf("Failed to convert response to description: %s", convertErr.Error())
	}
	finished <- done.Done{}
}

// __getSummaries fetches a page of vulnerability summaries and returns the next
// page's identifier, or an empty string if there is not one.
func __getSummaries(
	base *url.URL,
	ext string,
	summaries chan<- summary,
	errs chan<- error,
) string {
	endpt, _ := url.Parse(ext)
	toReq := base.ResolveReference(endpt)

	response, err := http.Get(toReq.String())
	if err != nil {
		log.Errorf("Encountered an error in __getSummaries: '%s'", err)
		errs <- err
		return ""
	}
	defer response.Body.Close()
	log.Debug("Got some vuln summaries")

	respJSON := map[string]interface{}{}
	decoder := json.NewDecoder(response.Body)
	decodeErr := decoder.Decode(&respJSON)
	if decodeErr != nil {
		log.Errorf("Encountered an error in __getSummaries: '%s'", decodeErr)
		errs <- decodeErr
		return ""
	}

	if errMsg, convertErr := __toErrorResponse(respJSON); convertErr == nil {
		log.Errorf("Clair responded with an error: '%s'", errMsg.Error.Message)
		errs <- errors.New(errMsg.Error.Message)
		return ""
	}
	if success, convertErr := __toSummaryResponse(respJSON); convertErr == nil {
		for _, vuln := range success.Vulnerabilities {
			summaries <- vuln
		}

		if success.NextPage != nil {
			return *success.NextPage
		}
		return ""
	}
	return ""
}

func __toErrorResponse(jsonData map[string]interface{}) (errorResponse, error) {
	theError := errors.New("Not an error response")

	if err, ok := jsonData["Error"].(map[string]interface{}); ok {
		if msg, ok := err["Message"].(string); ok {
			errResp := errorResponse{
				Error: message{
					Message: msg,
				},
			}
			return errResp, nil
		} else {
			return errorResponse{}, theError
		}
	}
	return errorResponse{}, theError
}

func __toSummaryResponse(jsonData map[string]interface{}) (summaryResponse, error) {
	sumResp := summaryResponse{}
	theError := errors.New("Not a summary response")

	if nextPage, ok := jsonData["NextPage"].(string); ok {
		sumResp.NextPage = new(string)
		*sumResp.NextPage = nextPage
	}

	if vulnBlobs, ok := jsonData["Vulnerabilities"].([]interface{}); ok {
		for _, vulnBlob := range vulnBlobs {
			vulnJSON, _ := vulnBlob.(map[string]interface{})
			if name, ok := vulnJSON["Name"].(string); ok {
				sumResp.Vulnerabilities = append(sumResp.Vulnerabilities, summary{name})
			} else {
				return summaryResponse{}, theError
			}
		}
	} else {
		return summaryResponse{}, theError
	}

	return sumResp, nil
}

func __toDescriptionResponse(jsonData map[string]interface{}) (descriptionResponse, error) {
	desc := descriptionResponse{}
	theErrorFmt := "Not a vulnerability description. Missing or invalid field %s"

	vulnBlob, ok := jsonData["Vulnerability"].(map[string]interface{})
	if !ok {
		return descriptionResponse{}, fmt.Errorf(theErrorFmt, "Vulnerability")
	}

	if name, ok := vulnBlob["Name"].(string); ok {
		desc.Vulnerability.Name = name
	} else {
		return descriptionResponse{}, fmt.Errorf(theErrorFmt, "Name")
	}

	if link, ok := vulnBlob["Link"].(string); ok {
		desc.Vulnerability.Link = link
	} else {
		return descriptionResponse{}, fmt.Errorf(theErrorFmt, "Link")
	}

	if severity, ok := vulnBlob["Severity"].(string); ok {
		desc.Vulnerability.Severity = severity
	} else {
		return descriptionResponse{}, fmt.Errorf(theErrorFmt, "Severity")
	}

	if fixBlobs, ok := vulnBlob["FixedIn"].([]interface{}); ok {
		for _, blob := range fixBlobs {
			newFix := fix{}
			fixJSON, _ := blob.(map[string]interface{})

			if name, ok := fixJSON["Name"].(string); ok {
				newFix.Name = name
			} else {
				return descriptionResponse{}, fmt.Errorf(theErrorFmt, "FixedIn[i].Name")
			}

			if version, ok := fixJSON["Version"].(string); ok {
				newFix.Version = version
			} else {
				return descriptionResponse{}, fmt.Errorf(theErrorFmt, "FixedIn[i].Version")
			}

			desc.Vulnerability.FixedIn = append(desc.Vulnerability.FixedIn, newFix)
		}
	} else {
		return descriptionResponse{}, fmt.Errorf(theErrorFmt, "FixedIn")
	}

	return desc, nil
}

func (stream Stream) Vulnerabilities(pform platform.Platform) vulnerability.Job {
	job := vulnerability.Job{
		Vulns:    make(chan vulnerability.Vulnerability),
		Finished: make(chan done.Done),
		Errors:   make(chan error),
	}

	go __stream(stream, pform, job)
	return job
}

func __stream(stream Stream, pform platform.Platform, job vulnerability.Job) {
	summaries, sumFinished, sumErrs := summarizeVulnerabilities(
		stream.config,
		stream.block,
		pform)
	finishedSummarizing := false
	jobsFinished := make(chan done.Done)
	jobs := 0

	for jobs > 0 || !finishedSummarizing {
		select {
		case sum := <-summaries:
			<-stream.block()
			mappedJob := vulnerability.Job{
				Vulns:    job.Vulns,
				Finished: jobsFinished,
				Errors:   job.Errors,
			}
			go __fetchDescription(stream, pform, sum, mappedJob)
			jobs++

		case <-sumFinished:
			finishedSummarizing = true

		case <-jobsFinished:
			jobs--

		case err := <-sumErrs:
			job.Errors <- err
		}
	}

	job.Finished <- done.Done{}
}

func __fetchDescription(
	stream Stream,
	pform platform.Platform,
	sum summary,
	job vulnerability.Job,
) {
	descriptions, descFinished, descErrs := describeVulnerability(
		stream.config,
		stream.block,
		sum.Name,
		pform)

readall:
	for {
		select {
		case desc := <-descriptions:
			job.Vulns <- toVulnerability(desc, pform)
			break readall

		case <-descFinished:
			break readall

		case err := <-descErrs:
			job.Errors <- err
		}
	}

	job.Finished <- done.Done{}
}
