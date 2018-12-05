package scanners

import (
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
	schedule limit.RateLimiter
	ticks    chan signal
}

// Re-use the Job structure as the output from jobRunner.
// It's all just plumbing.
type stream vulnerability.Job

type jobRunner struct {
	client vulnerability.Source
	pform  platform.Platform
}

func newScheduler(freq time.Duration) scheduler {
	return scheduler{
		schedule: limit.ConstantRateLimiter(freq),
	}
}

// Run starts an Agent process of periodically scanning
func (agent Agent) Run() {
}

func (sched *scheduler) clock() <-chan signal {
	return sched.ticks
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
