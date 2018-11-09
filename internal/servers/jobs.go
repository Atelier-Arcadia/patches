package servers

import (
	"github.com/zsck/patches/pkg/done"
	"github.com/zsck/patches/pkg/vulnerability"
)

// VulnJobManager manages "jobs" containing channels from which vulnerabilities
// are read.
type VulnJobManager struct {
}

// VulnJobManagerOptions are optional configuration parameters for VulnJobManager.
type VulnJobManagerOptions struct {
	MaxJobs uint
}

// FetchVulnsJob represents a job managed by the VulnJobManager.
type FetchVulnsJob struct {
	vulns    <-chan vulnerability.Vulnerability
	finished <-chan done.Done
	errs     <-chan error
}

// NewVulnJobManager constructs a new VulnJobManager.
func NewVulnJobManager(opts VulnJobManagerOptions) VulnJobManager {
	return VulnJobManager{}
}

// NewFetchVulnsJob constructs a new FetchVulnsJob.
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

// Register attempts to add a new job to the manager, returning an ID that
// must be provided during lookups.
func (jobs VulnJobManager) Register(job FetchVulnsJob) (string, error) {
	return "", nil
}

// Lookup retrieves a job being handled by the manager so results can be read from it.
func (jobs VulnJobManager) Lookup(jobID string) (FetchVulnsJob, bool) {
	return FetchVulnsJob{}, false
}
