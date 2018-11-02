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

	// Collect makes requests to the Clair API until it has enumerated all of the
	// pages containing names of vulnerabilities for the platform requested.
	__collect := func() {
		base, err := url.Parse(config.BaseURL)
		if err != nil {
			errs <- err
			return
		}

		__toErrorResponse := func(jsonData map[string]interface{}) (errorResponse, error) {
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

		__toSummaryResponse := func(jsonData map[string]interface{}) (summaryResponse, error) {
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

		// __get fetches a page of vulnerability summaries and returns the next
		// page's identifier, or an empty string if there is not one.
		__get := func(ext string) string {
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

		nextPage := __get(fmt.Sprintf(vulnSummariesWithoutPageEndptFmt, platform))
		for nextPage != "" {
			nextPage = __get(fmt.Sprintf(vulnSummariesWithPageEndptFmt, platform, nextPage))
		}
		finished <- done.Done{}
	}

	go __collect()
	return summaries, finished, errs
}

func (p Platform) String() string {
	return p.distro + ":" + p.version
}
