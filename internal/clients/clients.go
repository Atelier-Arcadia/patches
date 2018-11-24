package clients

import (
	"github.com/arcrose/patches/pkg/done"
	"github.com/arcrose/patches/pkg/platform"
	"github.com/arcrose/patches/pkg/vulnerability"
)

// ClairClient is capable of communicating with a vulnerability source over HTTP.
type ClairClient struct {
	serverAddr string
	serverPort uint16
}

// NewClairClient constructs a ClairClient.
func NewClairClient(addr string, port uint16) ClairClient {
	return ClairClient{
		serverAddr: addr,
		serverPort: port,
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
	finished <- done.Done{}
}
