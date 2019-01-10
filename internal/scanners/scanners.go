package scanners

import (
	"fmt"
	"os"
	ossignal "os/signal"
	"syscall"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/arcrose/patches/pkg/done"
	"github.com/arcrose/patches/pkg/pack"
	"github.com/arcrose/patches/pkg/platform"
	"github.com/arcrose/patches/pkg/vulnerability"

	"github.com/arcrose/patches/internal/limit"
	"github.com/arcrose/patches/internal/scanners/dpkg"
	"github.com/arcrose/patches/internal/scanners/rpm"
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
	Findings      chan<- vulnerability.Vulnerability
}

// NilScanner is a Scanner that does nothing and always returns Notfound.
type NilScanner struct{}

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

type setupFn func(map[string]interface{}) (pack.Scanner, error)

// Lookup attempts to set up a scanner for the desired platform.
func Lookup(pform platform.Platform, cfg map[string]interface{}) (pack.Scanner, error) {
	setup, found := supported()[pform]
	if !found {
		return NilScanner{}, fmt.Errorf("Cannot set up a scanner for '%s'", pform.String())
	}

	scanner, err := setup(cfg)
	if err != nil {
		return NilScanner{}, fmt.Errorf("Failed to set up scanner: '%s'", err.Error())
	}

	return scanner, nil
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

func supported() map[platform.Platform]setupFn {
	return map[platform.Platform]setupFn{
		platform.CentOS5:        setupRpm,
		platform.CentOS6:        setupRpm,
		platform.CentOS7:        setupRpm,
		platform.Debian8:        setupDpkg,
		platform.Debian9:        setupDpkg,
		platform.Debian10:       setupDpkg,
		platform.DebianUnstable: setupDpkg,
		//platform.Alpine3_3:      setupApk,
		//platform.Alpine3_4:      setupApk,
		//platform.Alpine3_5:      setupApk,
		//platform.Alpine3_6:      setupApk,
		//platform.Alpine3_7:      setupApk,
		//platform.Alpine3_8:      setupApk,
		platform.Oracle5:     setupRpm,
		platform.Oracle6:     setupRpm,
		platform.Oracle7:     setupRpm,
		platform.Ubuntu12_04: setupDpkg,
		platform.Ubuntu12_10: setupDpkg,
		platform.Ubuntu13_04: setupDpkg,
		platform.Ubuntu13_10: setupDpkg,
		platform.Ubuntu14_04: setupDpkg,
		platform.Ubuntu14_10: setupDpkg,
		platform.Ubuntu15_04: setupDpkg,
		platform.Ubuntu15_10: setupDpkg,
		platform.Ubuntu16_04: setupDpkg,
		platform.Ubuntu16_10: setupDpkg,
		platform.Ubuntu17_04: setupDpkg,
		platform.Ubuntu17_10: setupDpkg,
		platform.Ubuntu18_04: setupDpkg,
	}
}

func setupDpkg(cfg map[string]interface{}) (pack.Scanner, error) {
	compareFn, ok := cfg["compareFn"].(pack.VersionCompareFunc)
	if !ok {
		err := fmt.Errorf("Scanner configuration is missing a valid 'compareFn'")
		return NilScanner{}, err
	}

	return dpkg.NewDPKG(compareFn), nil
}

func setupRpm(cfg map[string]interface{}) (pack.Scanner, error) {
	var compareFn, ok = cfg["compareFn"].(pack.VersionCompareFunc)
	if !ok {
		var err = fmt.Errorf("Scanner configuration is missing a valid 'compareFn'")
		return NilScanner{}, err
	}

	return rpm.NewRPM(compareFn), nil
}

// Run starts an Agent process of periodically scanning for vulnerable
// packages pulled from a source.
func (agent Agent) Run() {
	sched := newScheduler(agent.ScanFrequency)
	sched.start()
	runner := newJobRunner(
		agent.VulnSource,
		agent.Platform,
		sched.clock())
	stream := runner.start()

	// Stop everything when the agent process exits
	defer func() {
		sched.stop()
		runner.stop()
	}()

	sigChan := make(chan os.Signal, 1)
	ossignal.Notify(
		sigChan,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	log.Infof("Starting main Agent process")
agent:
	for {
		select {
		case vuln := <-stream.Vulns:
			anyFound := false
			for _, pkg := range vuln.FixedInPackages {
				found, err := agent.SystemScanner.Scan(pkg)
				if found == pack.WasFound {
					anyFound = true
					break
				}
				if err != nil {
					log.Errorf("Scanner error: '%s'", err.Error())
				}
			}
			if !anyFound {
				agent.Findings <- vuln
			}

		case err := <-stream.Errors:
			log.Error(err)

		case <-stream.Finished:
			break agent

		case <-sigChan:
			break agent
		}
	}
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
	log.Infof("Starting job runner")

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

func (_ NilScanner) Scan(_ pack.Package) (pack.Found, error) {
	return pack.NotFound, nil
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
