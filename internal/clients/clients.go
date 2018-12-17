package clients

import (
	"encoding/json"
	"fmt"
	"net/http"

	log "github.com/Sirupsen/logrus"

	"github.com/arcrose/patches/pkg/done"
	"github.com/arcrose/patches/pkg/platform"
	"github.com/arcrose/patches/pkg/vulnerability"

	"github.com/arcrose/patches/internal/limit"
)

const startFetchEndptFmt string = "%s/vulns?platform=%s"
const continueFetchEndptFmt string = "%s/vulns?platform=%s&requestID=%s"

// ClairClient is capable of communicating with a vulnerability source over HTTP.
type ClairClient struct {
	serverAddr string
	block      limit.RateLimiter
}

type clairServerResponse struct {
	Error           *string                       `json:"error"`
	RequestID       string                        `json:"requestID"`
	Finished        bool                          `json:"finished"`
	Vulnerabilities []vulnerability.Vulnerability `json:"vulns"`
}

// NewClairClient constructs a ClairClient.
func NewClairClient(addr string, limiter limit.RateLimiter) ClairClient {
	return ClairClient{
		serverAddr: addr,
		block:      limiter,
	}
}

// Vulnerabilities streams vulnerabilities retrieved from a Patches server.
func (client ClairClient) Vulnerabilities(pform platform.Platform) vulnerability.Job {
	vulns := make(chan vulnerability.Vulnerability)
	finished := make(chan done.Done)
	errs := make(chan error)

	go __retrieve(client, pform, vulns, finished, errs)

	return vulnerability.Job{
		Vulns:    vulns,
		Finished: finished,
		Errors:   errs,
	}
}

func __retrieve(
	client ClairClient,
	pform platform.Platform,
	vulns chan<- vulnerability.Vulnerability,
	finished chan<- done.Done,
	errs chan<- error,
) {
	requestID := ""

	for {
		url := ""
		if requestID == "" {
			url = fmt.Sprintf(
				startFetchEndptFmt,
				client.serverAddr,
				pform.String())
		} else {
			url = fmt.Sprintf(
				continueFetchEndptFmt,
				client.serverAddr,
				pform.String(),
				requestID)
		}

		log.Infof("Requesting %s", url)

		resp, err := http.Get(url)
		if err != nil {
			errs <- err
			log.Error(err)
			break
		}

		respData := clairServerResponse{}
		decoder := json.NewDecoder(resp.Body)
		decodeErr := decoder.Decode(&respData)
		resp.Body.Close()
		if decodeErr != nil {
			errs <- decodeErr
			log.Error(decodeErr)
			break
		}

		if respData.Error != nil {
			err := fmt.Errorf("%s", *respData.Error)
			errs <- err
			log.Error(err)
			break
		}

		for _, vuln := range respData.Vulnerabilities {
			vulns <- vuln
		}

		if respData.Finished {
			break
		}

		requestID = respData.RequestID

		<-client.block()
	}

	finished <- done.Done{}
}
