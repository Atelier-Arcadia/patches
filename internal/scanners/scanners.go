package scanners

import (
	"errors"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/arcrose/patches/pkg/done"
	"github.com/arcrose/patches/pkg/pack"
	"github.com/arcrose/patches/pkg/platform"
	"github.com/arcrose/patches/pkg/vulnerability"

	"github.com/arcrose/patches/internal/limit"
)

// ErrCancelled may be returned by a call to Cancel.Confirm, indicating that
// a process tried to confirm that it is terminating more than once.
var ErrCancelled error = errors.New("already cancelled")

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

// Cancel provides a means of instructing a process to terminate.
type Cancel struct {
	terminate   chan done.Done
	confirm     chan done.Done
	isCancelled bool
}

type scheduler struct {
	schedule   limit.RateLimiter
	ticks      chan<- bool
	started    bool
	killSignal Cancel
}

// Re-use the Job structure as the output from jobRunner.
// It's all just plumbing.
type stream vulnerability.Job

type jobRunner struct {
	queued      uint
	jobFinished bool
	client      vulnerability.Source
	pform       platform.Platform
	runSignal   <-chan bool
	killSignal  Cancel
}

// NewCancel constructs a Cancel for signalling desire to terminate a process.
func NewCancel() Cancel {
	return Cancel{
		terminate:   make(chan done.Done, 1),
		confirm:     make(chan done.Done, 1),
		isCancelled: false,
	}
}

func newScheduler(freq time.Duration, out chan<- bool) scheduler {
	return scheduler{
		limit.ConstantRateLimiter(freq),
		out,
		false,
		NewCancel(),
	}
}

func newJobRunner(
	source vulnerability.Source,
	pform platform.Platform,
	signal <-chan bool,
) jobRunner {
	return jobRunner{
		queued:      0,
		jobFinished: true,
		client:      source,
		pform:       pform,
		runSignal:   signal,
		killSignal:  NewCancel(),
	}
}

// Run starts an Agent process of periodically scanning
func (agent Agent) Run() Cancel {
	return NewCancel()
}

// Send a signal to terminate the owner of the Cancel.
// This method blocks until the owner confirms that it has received
// the termination signal and will exit.
func (cancel *Cancel) Terminate() {
	if cancel.isCancelled {
		return
	}
	cancel.terminate <- done.Done{}
	<-cancel.confirm
	cancel.isCancelled = true
}

// Check will determine whether a signal has been sent to cancel the owner.
func (cancel *Cancel) Check() bool {
	select {
	case <-cancel.terminate:
		return true

	default:
		return false
	}
}

// Confirm should be called by owners of a Cancel to indicate that it
// (the owner) has received a terminate signal and will exit immediately.
func (cancel *Cancel) Confirm() error {
	if cancel.isCancelled {
		return ErrCancelled
	}
	cancel.confirm <- done.Done{}
	return nil
}

func (sched *scheduler) start() error {
	if sched.started {
		return errors.New("cannot start a scheduler more than once")
	}
	sched.started = true

	go func() {
		block := sched.schedule

		for {
			<-block()
			if sched.killSignal.Check() {
				sched.killSignal.Confirm()
				return
			}
			sched.ticks <- true
		}
	}()

	return nil
}

func (sched *scheduler) stop() error {
	if !sched.started {
		return errors.New("cannot stop a scheduler that has not been started")
	}

	sched.killSignal.Terminate()
	sched.started = false
	return nil
}

func (runner *jobRunner) start() stream {
	s := stream{
		Vulns:    make(chan vulnerability.Vulnerability),
		Finished: make(chan done.Done),
		Errors:   make(chan error),
	}

	go __stream(&s, runner)

	return s
}

func (runner jobRunner) stop() {
	runner.killSignal.Terminate()
	log.Debugf("Stopped")
}

func __stream(s *stream, runner *jobRunner) {
	killSignal := __handleKillSignal(runner.killSignal)

top:
	for {
		select {
		case <-runner.runSignal:
			log.Debugf("stream got run signal")
			__handleSignal(s, runner, killSignal)

		case <-killSignal:
			log.Debugf("stream got kill signal")
			break top
		}
	}
}

func __handleKillSignal(cancel Cancel) chan done.Done {
	signal := make(chan done.Done)

	go func() {
		for {
			<-time.After(100 * time.Millisecond)
			if cancel.Check() {
				log.Debugf("Got kill signal")
				signal <- done.Done{}
				return
			}
		}
	}()

	return signal
}

func __handleSignal(s *stream, runner *jobRunner, killSignal chan done.Done) {
	if !runner.jobFinished {
		log.Debugf("Queuing a job")
		runner.queued++
		return
	}

	log.Debugf("Starting a job")
	job := runner.client.Vulnerabilities(runner.pform)
	runner.jobFinished = false

	go func() {
	top:
		for {
			select {
			case vuln := <-job.Vulns:
				log.Debugf("Got a vuln")
				s.Vulns <- vuln

			case <-job.Finished:
				runner.jobFinished = true

			case err := <-job.Errors:
				log.Debugf("Got an error '%s'", err.Error())
				s.Errors <- err

			case <-killSignal:
				log.Debugf("handleSignal: kill signal recv")
				killSignal <- done.Done{}
				break top
			}
		}
	}()
}
