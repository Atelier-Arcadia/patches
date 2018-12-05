package scanners

import (
	"fmt"
	"testing"

	"github.com/arcrose/patches/pkg/done"
	"github.com/arcrose/patches/pkg/platform"
	"github.com/arcrose/patches/pkg/vulnerability"
)

type mockSource struct {
	numVulns uint
	numErrs  uint
}

func TestScheduler(t *testing.T) {
}

func TestJobRunner(t *testing.T) {
}

func (mock mockSource) Vulnerabilities(pform platform.Platform) vulnerability.Job {
	vulns := make(chan vulnerability.Vulnerability, mock.numVulns)
	finished := make(chan done.Done, 1)
	errors := make(chan error)

	go func() {
		var i uint
		for i = 0; i < mock.numVulns; i++ {
			vulns <- vulnerability.Vulnerability{}
			fmt.Println("Wrote a vuln")
		}
		for i = 0; i < mock.numErrs; i++ {
			errors <- fmt.Errorf("")
			fmt.Println("Wrote an error")
		}
		finished <- done.Done{}
	}()

	return vulnerability.Job{
		vulns,
		finished,
		errors,
	}
}
