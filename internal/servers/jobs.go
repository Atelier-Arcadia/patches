package servers

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/zsck/patches/pkg/done"
	"github.com/zsck/patches/pkg/vulnerability"
)

var defaultReadTimeout time.Duration = 30 * time.Millisecond

const (
	defaultMaxJobs uint = 128

	numJobIDBytes uint = 16
)

// VulnJobManager manages "jobs" containing channels from which vulnerabilities
// are read.
type VulnJobManager struct {
	managing    map[string]FetchVulnsJob
	numManaged  uint
	maxJobs     uint
	maxReadTime time.Duration
}

// VulnJobManagerOptions are optional configuration parameters for VulnJobManager.
type VulnJobManagerOptions struct {
	MaxJobs     uint
	ReadTimeout time.Duration
}

// FetchVulnsJob represents a job managed by the VulnJobManager.
type FetchVulnsJob struct {
	vulns    <-chan vulnerability.Vulnerability
	finished <-chan done.Done
	errs     <-chan error
}

// NewVulnJobManager constructs a new VulnJobManager.
func NewVulnJobManager(opts VulnJobManagerOptions) VulnJobManager {
	opts.applyDefaults()
	return VulnJobManager{
		managing:    make(map[string]FetchVulnsJob),
		numManaged:  0,
		maxJobs:     opts.MaxJobs,
		maxReadTime: opts.ReadTimeout,
	}
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
	if jobs.numManaged >= jobs.maxJobs {
		return "", errors.New("job queue full; try again later")
	}

	newID := generateID(numJobIDBytes, func(id string) bool {
		_, found := jobs.managing[id]
		return !found
	})

	jobs.managing[newID] = job
	jobs.numManaged++
	return newID, nil
}

// Retrieve finds a job being handled by the manager and reads results from it.
func (jobs VulnJobManager) Retrieve(jobID string) ([]vulnerability.Vulnerability, []error) {
	job, found := jobs.managing[jobID]
	vulns := []vulnerability.Vulnerability{}
	errs := []error{}

	if !found {
		return []vulnerability.Vulnerability{}, []error{errors.New("no such job")}
	}

	stopAt := time.Now().Add(jobs.maxReadTime)

readUntilTimeout:
	for {
		timeLeft := time.Until(stopAt)
		select {
		case <-time.After(timeLeft):
			break readUntilTimeout

		case <-job.finished:
			delete(jobs.managing, jobID)
			jobs.numManaged--
			break readUntilTimeout

		case err := <-job.errs:
			errs = append(errs, err)

		case vuln := <-job.vulns:
			vulns = append(vulns, vuln)
		}
	}

	return vulns, errs
}

func (opts *VulnJobManagerOptions) applyDefaults() {
	if opts.MaxJobs == 0 {
		opts.MaxJobs = defaultMaxJobs
	}
	if opts.ReadTimeout == 0 {
		opts.ReadTimeout = defaultReadTimeout
	}
}

func generateID(numBytes uint, unique func(string) bool) string {
	buffer := make([]byte, numBytes)
	for {
		bytesRead, err := rand.Read(buffer)
		if err != nil || bytesRead < 0 || uint(bytesRead) < numBytes {
			continue
		}
		encoded := hex.EncodeToString(buffer)
		if unique(encoded) {
			return encoded
		}
	}
}
