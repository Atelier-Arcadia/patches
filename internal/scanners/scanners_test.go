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
	sched := newScheduler(100 * time.Millisecond)

	if err := sched.start(); err != nil {
		t.Errorf("Should have been able to start scheduler but got error '%s'", err.Error())
	}
	if err := sched.start(); err == nil {
		t.Errorf("Should not have been able to start scheduler a second time")
	}

	ticks := sched.clock()
	ticksCounted := 0
	finished := make(chan bool, 1)

	go func() {
		stop := time.Now().Add(350 * time.Millisecond)

	top:
		for {
			timeLeft := stop.Sub(time.Now())

			select {
			case <-ticks:
				ticksCounted++

			case <-time.After(timeLeft):
				finished <- true
				break top
			}
		}
	}()

	<-finished

	if ticksCounted != 3 {
		t.Errorf("Should have read 3 ticks from clock")
	}

	if err := sched.stop(); err != nil {
		t.Errorf("Should have been able to stop scheduler, but got error '%s'", err.Error())
	}
	if err := sched.stop(); err == nil {
		t.Errorf("Should not have been able to stop scheduler a second time")
	}

	select {
	case <-sched.clock():
		t.Errorf("Should not receive clock ticks after stopping scheduler")

	case <-time.After(250 * time.Millisecond):
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
