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
	testCases := []struct {
		Description   string
		TimesToSignal uint
		SignalPause   time.Duration
		VulnsToGen    uint
		ErrsToGen     uint
	}{
		{
			Description:   "Should read all of the vulns and errors produced by the runner",
			TimesToSignal: 1,
			SignalPause:   1 * time.Second,
			VulnsToGen:    3,
			ErrsToGen:     2,
		},
		{
			Description:   "Should read everything written by multiple jobs",
			TimesToSignal: 4,
			SignalPause:   1 * time.Second,
			VulnsToGen:    2,
			ErrsToGen:     1,
		},
	}

	for caseNum, tcase := range testCases {
		t.Logf("Running TestJobRunner case #%d: %s", caseNum, tcase.Description)

		signals := make(chan signal, tcase.TimesToSignal)
		runner := newJobRunner(
			mockSource{tcase.VulnsToGen, tcase.ErrsToGen},
			platform.Debian8,
			signals)

		finished := make(chan bool, 1)
		go func() {
			var i uint
			for i = 0; i < tcase.TimesToSignal; i++ {
				signals <- signal(true)
				<-time.After(tcase.SignalPause)
			}
			finished <- true
		}()

		var vulnsCounted uint = 0
		var errsCounted uint = 0
		errs := []error{}
		stream := runner.start()

	top:
		for {
			select {
			case <-stream.Vulns:
				vulnsCounted++

			case <-stream.Errors:
				errsCounted++

			case <-finished:
				runner.stop()
				break top
			}
		}

		expected := tcase.VulnsToGen * tcase.TimesToSignal
		if vulnsCounted != expected {
			errs = append(errs, fmt.Errorf(
				"Expected to get %d vulns, but only got %d",
				expected,
				vulnsCounted))
		}
		expected = tcase.ErrsToGen * tcase.TimesToSignal
		if errsCounted != expected {
			errs = append(errs, fmt.Errorf(
				"Expected to get %d errs, but only got %d",
				expected,
				errsCounted))
		}

		for _, err := range errs {
			t.Error(err)
		}
	}
}

func (mock mockSource) Vulnerabilities(pform platform.Platform) vulnerability.Job {
	vulns := make(chan vulnerability.Vulnerability)
	finished := make(chan done.Done)
	errors := make(chan error)

	go func() {
		var i uint
		for i = 0; i < mock.numVulns; i++ {
			vulns <- vulnerability.Vulnerability{}
		}
		for i = 0; i < mock.numErrs; i++ {
			errors <- fmt.Errorf("")
		}
		finished <- done.Done{}
	}()

	return vulnerability.Job{
		vulns,
		finished,
		errors,
	}
}
