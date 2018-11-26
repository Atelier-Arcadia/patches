package scanners

import (
	log "github.com/Sirupsen/logrus"

	"github.com/arcrose/patches/pkg/done"
	"github.com/arcrose/patches/pkg/pack"
	"github.com/arcrose/patches/pkg/platform"
	"github.com/arcrose/patches/pkg/vulnerability"

	"github.com/arcrose/patches/internal/limit"
)

type Scheduler struct {
	schedule  limit.RateLimiter
	client    vulnerability.Source
	pform     platform.Platform
	terminate chan done.Done
	confirm   chan done.Done
}

type Agent struct {
	scanner  pack.Scanner
	schedule Scheduler
}

type fetchJob struct {
	vulns    <-chan vulnerability.Vulnerability
	finished <-chan done.Done
	errs     <-chan error
}

func NewScheduler(
	schedule limit.RateLimiter,
	client vulnerability.Source,
	pform platform.Platform,
) Scheduler {
	return Scheduler{
		schedule,
		client,
		pform,
		terminate: make(chan done.Done),
	}
}

func NewAgent(scan pack.Scanner, scheduler Scheduler) Agent {
	return Agent{
		scan,
		scheduler,
	}
}

func (agent Agent) Run() {
	vulns, errs := agent.scheduler.start()

readall:
	for {
		select {
		case vuln := <-vulns:
			log.Infof("Got a vuln: %s", vuln.String())

		case err := <-errs:
			log.Error(err)
		}
	}
}

func (scheduler Scheduler) start() (
	<-chan vulnerability.Vulnerability,
	<-chan error,
) {
	vulnPipe := make(chan vulnerability.Vulnerability)
	errPipe := make(chan error)

	go __runJobs(scheduler, vulnPipe, errPipe)

	return vulnPipe, errPipe
}

func (scheduler Scheduler) stop() {
	scheduler.terminate <- done.Done{}
	<-scheduler.confirm
}

func __runJobs(
	scheduler Scheduler,
	vulns chan<- vulnerability.Vulnerability,
	errs chan<- error,
) {
}

func __spawn(client vulnerability.Source, pform platform.Platform) fetchJob {
	vulns, finished, errs := client.Vulnerabilities(pform)
	return fetchJob{
		vulns,
		finished,
		errs,
	}
}
