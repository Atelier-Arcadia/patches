package clair

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/zsck/patches/pkg/done"
	"github.com/zsck/patches/pkg/pack"
	"github.com/zsck/patches/pkg/platform"
	"github.com/zsck/patches/pkg/vulnerability"
)

const vulnSummariesWithoutPageEndptFmt string = "/v1/namespaces/%s/vulnerabilities?limit=100"
const vulnSummariesWithPageEndptFmt string = "/v1/namespaces/%s/vulnerabilities?page=%s&limit=100"
const vulnDescriptionEndptFmt string = "/v1/namespaces/%s/vulnerabilities/%s"

// ClairAPIv1 contains the configuration required to communicate with V1 of the Clair API.
type ClairAPIv1 struct {
	BaseURL string
}

// Stream implements the Source
type Stream struct {
	config ClairAPIv1
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
func NewStream(config ClairAPIv1) Stream {
	return Stream{
		config,
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

// summarizeVulnerabilities runs a goroutine that streams out summaries of
// vulnerabilities affecting a platform as described by the Clair v1 API.
func summarizeVulnerabilities(
	config ClairAPIv1,
	pform platform.Platform,
) (<-chan summary, <-chan done.Done, <-chan error) {
	summaries := make(chan summary)
	finished := make(chan done.Done)
	errs := make(chan error)

	go __collect(config, pform, summaries, finished, errs)
	return summaries, finished, errs
}

// describeVulnerability runs a goroutine that requests detailed infomration
// about a vulnerability affecting a platform from the Clair v1 API.
func describeVulnerability(
	config ClairAPIv1,
	vulnName string,
	pform platform.Platform,
) (<-chan description, <-chan done.Done, <-chan error) {
	descriptions := make(chan description)
	finished := make(chan done.Done)
	errs := make(chan error)

	go __describe(config, vulnName, pform, descriptions, finished, errs)
	return descriptions, finished, errs
}

// __collect makes requests to the Clair API until it has enumerated all of the
// pages containing names of vulnerabilities for the platform requested.
func __collect(
	cfg ClairAPIv1,
	pform platform.Platform,
	summaries chan<- summary,
	finished chan<- done.Done,
	errs chan<- error,
) {
	base, err := url.Parse(cfg.BaseURL)
	if err != nil {
		errs <- err
		finished <- done.Done{}
		return
	}

	ext := fmt.Sprintf(vulnSummariesWithoutPageEndptFmt, pform)
	nextPage := __getSummaries(base, ext, summaries, errs)
	for nextPage != "" {
		ext = fmt.Sprintf(vulnSummariesWithPageEndptFmt, pform, nextPage)
		nextPage = __getSummaries(base, ext, summaries, errs)
	}
	finished <- done.Done{}
}

// __describe performs a request to the Clair API to get detailed information
// about one specific vulnerability.
func __describe(
	cfg ClairAPIv1,
	vulnName string,
	pform platform.Platform,
	descriptions chan<- description,
	finished chan<- done.Done,
	errs chan<- error,
) {
	base, err := url.Parse(cfg.BaseURL)
	if err != nil {
		errs <- err
		finished <- done.Done{}
		return
	}

	ext := fmt.Sprintf(vulnDescriptionEndptFmt, pform, vulnName)
	endpt, _ := url.Parse(ext)
	toReq := base.ResolveReference(endpt)

	response, err := http.Get(toReq.String())
	if err != nil {
		errs <- err
		finished <- done.Done{}
		return
	}
	defer response.Body.Close()

	respJSON := map[string]interface{}{}
	decoder := json.NewDecoder(response.Body)
	decodeErr := decoder.Decode(&respJSON)
	if decodeErr != nil {
		errs <- decodeErr
		finished <- done.Done{}
		return
	}

	if errMsg, convertErr := __toErrorResponse(respJSON); convertErr == nil {
		errs <- errors.New(errMsg.Error.Message)
		finished <- done.Done{}
		return
	}
	if description, convertErr := __toDescriptionResponse(respJSON); convertErr == nil {
		descriptions <- description.Vulnerability
	} else {
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
		errs <- err
		return ""
	}
	defer response.Body.Close()

	respJSON := map[string]interface{}{}
	decoder := json.NewDecoder(response.Body)
	decodeErr := decoder.Decode(&respJSON)
	if decodeErr != nil {
		errs <- decodeErr
		return ""
	}

	if errMsg, convertErr := __toErrorResponse(respJSON); convertErr == nil {
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
	theError := errors.New("Not a vulnerability description")

	vulnBlob, ok := jsonData["Vulnerability"].(map[string]interface{})
	if !ok {
		return descriptionResponse{}, theError
	}

	if name, ok := vulnBlob["Name"].(string); ok {
		desc.Vulnerability.Name = name
	} else {
		return descriptionResponse{}, theError
	}

	if link, ok := vulnBlob["Link"].(string); ok {
		desc.Vulnerability.Link = link
	} else {
		return descriptionResponse{}, theError
	}

	if severity, ok := vulnBlob["Severity"].(string); ok {
		desc.Vulnerability.Severity = severity
	} else {
		return descriptionResponse{}, theError
	}

	if fixBlobs, ok := vulnBlob["FixedIn"].([]interface{}); ok {
		for _, blob := range fixBlobs {
			newFix := fix{}
			fixJSON, _ := blob.(map[string]interface{})

			if name, ok := fixJSON["Name"].(string); ok {
				newFix.Name = name
			} else {
				return descriptionResponse{}, theError
			}

			if version, ok := fixJSON["Version"].(string); ok {
				newFix.Version = version
			} else {
				return descriptionResponse{}, theError
			}

			desc.Vulnerability.FixedIn = append(desc.Vulnerability.FixedIn, newFix)
		}
	} else {
		return descriptionResponse{}, theError
	}

	return desc, nil
}

func (stream Stream) Vulnerabilities(pform platform.Platform) (
	<-chan vulnerability.Vulnerability,
	<-chan done.Done,
	<-chan error,
) {
	vulns := make(chan vulnerability.Vulnerability)
	finished := make(chan done.Done)
	errs := make(chan error)

	go __stream(stream, pform, vulns, finished, errs)
	return vulns, finished, errs
}

func __stream(
	stream Stream,
	pform platform.Platform,
	vulns chan<- vulnerability.Vulnerability,
	finished chan<- done.Done,
	errs chan<- error,
) {
	summaries, sumFinished, sumErrs := summarizeVulnerabilities(stream.config, pform)
	finishedSummarizing := false
	jobsFinished := make(chan done.Done)
	jobs := 0

	for jobs > 0 || !finishedSummarizing {
		select {
		case sum := <-summaries:
			go __fetchDescription(stream, pform, sum, vulns, jobsFinished, errs)
			jobs++

		case <-sumFinished:
			finishedSummarizing = true

		case <-jobsFinished:
			jobs--

		case err := <-sumErrs:
			errs <- err
		}
	}

	finished <- done.Done{}
}

func __fetchDescription(
	stream Stream,
	pform platform.Platform,
	sum summary,
	vulns chan<- vulnerability.Vulnerability,
	finished chan<- done.Done,
	errs chan<- error,
) {
	descriptions, descFinished, descErrs := describeVulnerability(
		stream.config,
		sum.Name,
		pform)

readall:
	for {
		select {
		case desc := <-descriptions:
			vulns <- toVulnerability(desc, pform)
			break readall

		case <-descFinished:
			break readall

		case err := <-descErrs:
			errs <- err
		}
	}

	finished <- done.Done{}
}
