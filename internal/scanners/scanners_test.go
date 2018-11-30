package scanners

import (
	"testing"
	"time"

	"github.com/arcrose/patches/pkg/done"
	"github.com/arcrose/patches/pkg/platform"
	"github.com/arcrose/patches/pkg/vulnerability"
)

type mockSource struct {
	numVulns uint
}

func TestCancel(t *testing.T) {
	cancel := NewCancel()
	go func() {
		for !cancel.Check() {
			<-time.After(50 * time.Millisecond)
		}
		if err := cancel.Confirm(); err != nil {
			t.Error(err)
		}
	}()
	cancel.Terminate()

	if err := cancel.Confirm(); err == nil {
		t.Errorf("Expected a second call to Cancel.Confirm to return an error")
	}
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
	type config struct {
		TimesToSignal   uint
		SignalPause     time.Time
		VulnsToProduce  uint
		ErrorsToProduce uint
	}

	testCases := []struct {
		Description string
		TestConfig  config
		Scenario    func(config, jobRunner) []error
	}{
		{
			Description: "Should stream out all vulnerabilities received",
			TestConfig: config{
				TimesToSignal:   1,
				VulnsToProduce:  13,
				ErrorsToProduce: 0,
			},
			Scenario: func(cfg config, runner jobRunner) []error {
				stream := runner.start()
				errs := []error{}

				vulnsReceived := 0
			readall:
				for {
					select {
					case <-stream.Vulns:
						vulnsReceived++

					case <-stream.Finished:
						break readall
					}
				}

				if vulnsReceived != cfg.VulnsToProduce {
					errs = append(errs, fmt.Errorf(
						"Expected %d vulns, got %d",
						cfg.VulnsToProduce,
						vulnsReceived))
				}

				return errs
			},
		},
		{
			Description: "Should stream out all errors received",
			TestConfig: config{
				TimesToSignal:   1,
				VulnsToProduce:  0,
				ErrorsToProduce: 5,
			},
			Scenario: func(cfg config, runner jobRunner) []error {
				stream := runner.start()
				errs := []error{}

				errsReceived := 0
			readall:
				for {
					select {
					case <-stream.Errors:
						errsReceived++

					case <-stream.Finished:
						break readall
					}
				}

				if errsReceived != cfg.ErrorsToProduce {
					errs = append(errs, fmt.Errorf(
						"Expected %d errors, got %d",
						cfg.ErrorsToProduce,
						errsReceived))
				}

				return errs
			},
		},
		{
			Description: "Should stream out everything received after multiple signals",
			TestConfig: config{
				TimesToSignal:   4,
				VulnsToProduce:  2,
				ErrorsToProduce: 1,
				SignalPause:     50 * time.Millisecond,
			},
			Scenario: func(cfg config, runner jobRunner) []error {
				stream := runner.start()
				errs := []error{}

				vulnsReceived := 0
				errsReceived := 0
			readall:
				for {
					select {
					case <-stream.Vulns:
						vulnsReceived++

					case <-stream.Errors:
						errsReceived++

					case <-stream.Finished:
						break readall
					}
				}

				expected := config.VulnsToProduce * config.TimesToSignal
				if vulnsReceived != expected {
					errs = append(errs, fmt.Errorf(
						"Expected %d vulns, got %d",
						expected,
						vulnsReceived))
				}

				expected = config.ErrorsToProduce * config.TimesToSignal
				if errsReceived != expected {
					errs = append(errs, fmt.Errorf(
						"Expected %d errors, got %d",
						expected,
						errsReceived))
				}

				return errs
			},
		},
		{
			Description: "Should only stream vulns when signal is sent",
			TestConfig: config{
				TimesToSignal:   2,
				VulnsToProduce:  1,
				ErrorsToProduce: 0,
				SignalPause:     2 * time.Second,
			},
			Scenario: func(cfg config, runner jobRunner) []error {
				stream := runner.start()
				errs := []error{}

				<-time.After(100 * time.Millisecond)
				select {
				case <-stream.Vulns:
					break

				case <-stream.Finished:
					errs = append(errs, fmt.Errorf("unexpectedly finished"))

				case <-stream.Errors:
					errs = append(errs, fmt.Errorf("got an error when none was expected"))
				}

				select {
				case <-stream.Vulns:
					errs = append(errs, fmt.Errorf("unexpectedly got a second vuln early"))

				case <-stream.Finished:
					errs = append(errs, fmt.Errorf("unexpectedly finished 2"))

				case <-stream.Errors:
					errs = append(errs, fmt.Errorf("got an error when none was expected 2"))

				default:
					break
				}

				return errs
			},
		},
	}

	for caseNum, testCase := range testCases {
		t.Logf("Running TestJobRunner case #%d: %s", caseNum, testCase.Description)

		signal := make(chan bool)
		runner := newJobRunner(
			mockSource(testCase.TestConfig.VulnsToProduce),
			platform.Debian8,
			signal)

		go func() {
			var i uint
			for i = 0; i < testCase.TestConfig.TimesToSignal; i++ {
				signal <- true
				<-time.After(testCase.TestConfig.SignalPause)
			}
		}()

		errs := testCase.Scenario(testCase.TestConfig, runner)

		for _, err := range errs {
			t.Error(err)
		}
	}
}

func (mock mockSource) Vulnerabilities(pform platform.Platform) vulnerability.Job {
	vulns := make(chan vuln.Vulnerability, mock.numVulns)
	finished := make(chan done.Done, 1)
	errors = make(chan error)

	go func() {
		var i uint
		for i = 0; i < mock.numVulns; i++ {
			vulns <- vulnerability.Vulnerability{}
		}
		finished <- done.Done{}
	}()

	return vulnerability.Job{
		vulns,
		finished,
		errors,
	}
}
