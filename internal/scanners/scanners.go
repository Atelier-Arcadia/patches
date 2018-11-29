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
	killSignal Cancel
}

type jobRunner struct {
	currentJob  *vulnerability.Job
	jobFinished bool
	client      vulnerability.Source
	pform       platform.Platform
	runTrigger  <-chan bool
	killSignal  Cancel
}

// NewCancel constructs a Cancel for signalling desire to terminate a process.
func NewCancel() Cancel {
	return Cancel{
		terminate:   make(chan done.Done),
		confirm:     make(chan done.Done),
		isCancelled: false,
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
