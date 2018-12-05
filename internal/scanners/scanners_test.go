package scanners

import (
	"fmt"
	"testing"
	"time"

	"github.com/arcrose/patches/pkg/done"
	"github.com/arcrose/patches/pkg/platform"
	"github.com/arcrose/patches/pkg/vulnerability"
)

type mockSource struct {
	numVulns uint
	numErrs  uint
}

func TestScheduler(t *testing.T) {
	ticks := make(chan bool, 5)
	schedule := newScheduler(100*time.Millisecond, ticks)

	if err := schedule.stop(); err == nil {
		t.Errorf("Should not be able to stop a scheduler that has not been started")
	}
	if err := schedule.start(); err != nil {
		t.Error(err)
	}
	if err := schedule.start(); err == nil {
		t.Errorf("Should not be able to start a scheduler twice")
	}
	<-time.After(350 * time.Millisecond)
	if err := schedule.stop(); err != nil {
		t.Error(err)
	}
	if err := schedule.stop(); err == nil {
		t.Errorf("Should not be able to stop a scheduler twice")
	}

	ticksReceived := 0
	for ticksReceived < 3 {
		<-ticks
		ticksReceived++
	}

	select {
	case <-ticks:
		t.Errorf("Schedule should not send any more ticks after being stopped")

	default:
		break
	}
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
