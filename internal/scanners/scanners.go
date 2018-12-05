package scanners

import (
	"fmt"
	"time"

	"github.com/arcrose/patches/pkg/done"
	"github.com/arcrose/patches/pkg/pack"
	"github.com/arcrose/patches/pkg/platform"
	"github.com/arcrose/patches/pkg/vulnerability"

	"github.com/arcrose/patches/internal/limit"
)

// Agent is a top-level type that contains all of the dependencies required to
// run a scanner.
// VulnSource is the source from which information about vulnerabilities can
// be retrieved.
// Platform is the platform the Agent is running on.
// ScanFrequency determines how frequently the Agent will start a scan.
// SystemScanner handles checking the host for a vulnerable package.
// Findings will have vulnerable packages found on the host written to it.
type Agent struct {
	VulnSource    vulnerability.Source
	Platform      platform.Platform
	ScanFrequency time.Duration
	SystemScanner pack.Scanner
	Findings      chan<- pack.Package
}

type signal bool

type scheduler struct {
	schedule  limit.RateLimiter
	ticks     chan signal
	isStarted bool
	terminate chan bool
	confirm   chan bool
}

// Re-use the Job structure as the output from jobRunner.
// It's all just plumbing.
type stream vulnerability.Job

type jobRunner struct {
	client    vulnerability.Source
	pform     platform.Platform
	signals   <-chan signal
	isRunning bool
	terminate chan bool
	confirm   chan bool
}

func newScheduler(freq time.Duration) scheduler {
	return scheduler{
		schedule:  limit.ConstantRateLimiter(freq),
		ticks:     make(chan signal),
		isStarted: false,
		terminate: make(chan bool, 1),
		confirm:   make(chan bool, 1),
	}
}

func newJobRunner(
	src vulnerability.Source,
	pform platform.Platform,
	signals <-chan signal,
) jobRunner {
	return jobRunner{
		client:    src,
		pform:     pform,
		signals:   signals,
		isRunning: false,
		terminate: make(chan bool, 1),
		confirm:   make(chan bool, 1),
	}
}

// Run starts an Agent process of periodically scanning
func (agent Agent) Run() {
}

func (sched *scheduler) clock() <-chan signal {
	return sched.ticks
}

func (sched *scheduler) start() error {
	if sched.isStarted {
		return fmt.Errorf("Scheduler already started")
	}

	go __runClock(sched)

	sched.isStarted = true
	return nil
}

func (sched *scheduler) stop() error {
	if !sched.isStarted {
		return fmt.Errorf("Scheduler is not running")
	}

	sched.terminate <- true
	<-sched.confirm

	sched.isStarted = false
	return nil
}

func (runner *jobRunner) start() stream {
	s := stream{
		Vulns:    make(chan vulnerability.Vulnerability),
		Finished: make(chan done.Done, 1),
		Errors:   make(chan error),
	}

	go __stream(&s, runner)

	runner.isRunning = true
	return s
}

func (runner jobRunner) stop() error {
	if !runner.isRunning {
		return fmt.Errorf("JobRunner is not running")
	}

	runner.terminate <- true
	<-runner.confirm

	runner.isRunning = false
	return nil
}

func __runClock(s *scheduler) {
	block := s.schedule

clock:
	for {
		select {
		case <-block():
			s.ticks <- signal(true)

		case <-s.terminate:
			s.confirm <- true
			break clock
		}
	}
}

func __stream(s *stream, runner *jobRunner) {
	jobRunning := false
	jobFinished := make(chan bool)
	killJob := make(chan bool)
	confirmKilled := make(chan bool)

stream:
	for {
		select {
		case <-runner.signals:
			if !jobRunning {
				job := runner.client.Vulnerabilities(runner.pform)
				go __runJob(s, job, jobFinished, killJob, confirmKilled)
				jobRunning = true
			}

		case <-jobFinished:
			jobRunning = false

		case <-runner.terminate:
			if jobRunning {
				killJob <- true
				<-confirmKilled
			}
			s.Finished <- done.Done{}
			runner.confirm <- true
			break stream
		}
	}
}

func __runJob(
	s *stream,
	job vulnerability.Job,
	jobFinished chan<- bool,
	kill <-chan bool,
	confirm chan<- bool,
) {
job:
	for {
		select {
		case vuln := <-job.Vulns:
			s.Vulns <- vuln

		case err := <-job.Errors:
			s.Errors <- err

		case <-job.Finished:
			jobFinished <- true
			break job

		case <-kill:
			confirm <- true
			break job
		}
	}
}
