package clients

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/arcrose/patches/pkg/done"
	"github.com/arcrose/patches/pkg/platform"
	"github.com/arcrose/patches/pkg/vulnerability"

	"github.com/arcrose/patches/internal/limit"
)

const startFetchEndptFmt string = "%s:%s/vulns?platform=%s"
const continueFetchEndptFmt string = "%s:%s/vulns?platform=%s&requestID=%s"

// ClairClient is capable of communicating with a vulnerability source over HTTP.
type ClairClient struct {
	serverAddr string
	serverPort uint16
	block      limit.RateLimiter
}

type clairServerResponse struct {
	Error           *string                       `json:"error"`
	RequestID       string                        `json:"requestID"`
	Finished        bool                          `json:"finished"`
	Vulnerabilities []vulnerability.Vulnerability `json:"vulns"`
}

// NewClairClient constructs a ClairClient.
func NewClairClient(addr string, port uint16, limiter limit.RateLimiter) ClairClient {
	return ClairClient{
		serverAddr: addr,
		serverPort: port,
		block:      limiter,
	}
}

// Vulnerabilities streams vulnerabilities retrieved from a Patches server.
func (client ClairClient) Vulnerabilities(pform platform.Platform) (
	<-chan vulnerability.Vulnerability,
	<-chan done.Done,
	<-chan error,
) {
	vulns := make(chan vulnerability.Vulnerability)
	finished := make(chan done.Done)
	errs := make(chan error)

	go __retrieve(client, pform, vulns, finished, errs)

	return vulns, finished, errs
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
				client.serverPort,
				pform.String())
		} else {
			url = fmt.Sprintf(
				continueFetchEndptFmt,
				client.serverAddr,
				client.serverPort,
				pform.String(),
				requestID)
		}

		resp, err := http.Get(url)
		if err != nil {
			errs <- err
			break
		}

		respData := clairServerResponse{}
		decoder := json.NewDecoder(resp.Body)
		decodeErr := decoder.Decode(&respData)
		resp.Body.Close()
		if decodeErr != nil {
			errs <- decodeErr
			break
		}

		if respData.Error != nil {
			errs <- fmt.Errorf("%s", *respData.Error)
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
