package scanners

import (
	"errors"
	"fmt"
	"time"

	log "github.com/Sirupsen/logrus"

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

type scheduler struct {
	schedule limit.RateLimiter
	ticks    chan<- bool
	started  bool
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
}

func newScheduler(freq time.Duration, out chan<- bool) scheduler {
	return scheduler{
		limit.ConstantRateLimiter(freq),
		out,
		false,
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
	}
}

// Run starts an Agent process of periodically scanning
func (agent Agent) Run() {
}

func (sched *scheduler) start() error {
	return nil
}

func (sched *scheduler) stop() error {
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
}

func __stream(s *stream, runner *jobRunner) {
}
