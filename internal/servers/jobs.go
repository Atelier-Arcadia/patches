package servers

import (
	"github.com/zsck/patches/pkg/done"
	"github.com/zsck/patches/pkg/vulnerability"
)

type VulnJobManager struct {
}

type VulnJobManagerOptions struct {
	MaxJobs   uint
	QueueSize uint
}

type FetchVulnsJob struct {
	vulns    <-chan vulnerability.Vulnerability
	finished <-chan done.Done
	errs     <-chan error
}

func NewVulnJobManager(opts VulnJobManagerOptions) VulnJobManager {
	return VulnJobManager{}
}

func NewFetchVulnsJob(
	vulns <-chan vulnerability.Vulnerability,
	finished <-chan done.Done,
	errs <-chan error,
) FetchVulnsJob {
	return FetchVulnsJob{
		vulns,
		finished,
		errs,
	}
}

func (jobs VulnJobManager) Register(job FetchVulnsJob) (string, error) {
	return "", nil
}

func (jobs VulnJobManager) Lookup(jobID string) (FetchVulnsJob, bool) {
	return FetchVulnsJob{}, false
}
