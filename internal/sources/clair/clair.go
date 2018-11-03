package clair

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/zsck/patches/pkg/done"
)

const vulnSummariesWithoutPageEndptFmt string = "/v1/namespaces/%s/vulnerabilities?limit=100"
const vulnSummariesWithPageEndptFmt string = "/v1/namespaces/%s/vulnerabilities?page=%s&limit=100"
const vulnDescriptionEndptFmt string = "/v1/namespaces/%s/vulnerabilities/%s"

// ClairAPIv1 contains the configuration required to communicate with V1 of the Clair API.
type ClairAPIv1 struct {
	BaseURL string
}

// Platform describes a Linux distribution for which the Clair API can provide
// information about vulnerable packages.
type Platform struct {
	distro  string
	version string
}

var (
	Debian8 Platform = Platform{
		distro:  "debian",
		version: "8",
	}
)

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

func GetVulnSummaries(
	config ClairAPIv1,
	platform Platform,
) (<-chan summary, <-chan done.Done, <-chan error) {
	s, d, e := summarizeVulnerabilities(config, platform)
	return s, d, e
}

// summarizeVulnerabilities runs a goroutine that streams out summaries of
// vulnerabilities affecting a platform as described by the Clair v1 API.
func summarizeVulnerabilities(
	config ClairAPIv1,
	platform Platform,
) (<-chan summary, <-chan done.Done, <-chan error) {
	summaries := make(chan summary)
	finished := make(chan done.Done)
	errs := make(chan error)

	go __collect(config, platform, summaries, finished, errs)
	return summaries, finished, errs
}

// describeVulnerability runs a goroutine that requests detailed infomration
// about a vulnerability affecting a platform from the Clair v1 API.
func describeVulnerability(
	config ClairAPIv1,
	vulnName string,
	platform Platform,
) (<-chan description, <-chan done.Done, <-chan error) {
	descriptions := make(chan description)
	finished := make(chan done.Done)
	errs := make(chan error)

	go __describe(config, vulnName, platform, descriptions, finished, errs)
	return descriptions, finished, errs
}

// __collect makes requests to the Clair API until it has enumerated all of the
// pages containing names of vulnerabilities for the platform requested.
func __collect(
	cfg ClairAPIv1,
	platform Platform,
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

	ext := fmt.Sprintf(vulnSummariesWithoutPageEndptFmt, platform)
	nextPage := __getSummaries(base, ext, summaries, errs)
	for nextPage != "" {
		ext = fmt.Sprintf(vulnSummariesWithPageEndptFmt, platform, nextPage)
		nextPage = __getSummaries(base, ext, summaries, errs)
	}
	finished <- done.Done{}
}

// __describe performs a request to the Clair API to get detailed information
// about one specific vulnerability.
func __describe(
	cfg ClairAPIv1,
	vulnName string,
	platform Platform,
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

	ext := fmt.Sprintf(vulnDescriptionEndptFmt, platform, vulnName)
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

	if name, ok := jsonData["Name"].(string); ok {
		desc.Vulnerability.Name = name
	} else {
		return descriptionResponse{}, theError
	}

	if link, ok := jsonData["Link"].(string); ok {
		desc.Vulnerability.Link = link
	} else {
		return descriptionResponse{}, theError
	}

	if severity, ok := jsonData["Severity"].(string); ok {
		desc.Vulnerability.Severity = severity
	} else {
		return descriptionResponse{}, theError
	}

	if fixBlobs, ok := jsonData["FixedIn"].([]interface{}); ok {
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

func (p Platform) String() string {
	return p.distro + ":" + p.version
}
