package servers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Atelier-Arcadia/patches/pkg/vulnerability"
)

var defaultReadTimeout time.Duration = 30 * time.Millisecond

var errNoSuchJob = "no such job"

const (
	defaultMaxJobs uint = 128

	numJobIDBytes uint = 16
)

type complete bool

// VulnJobManager manages "jobs" containing channels from which vulnerabilities
// are read.
type VulnJobManager struct {
	managing    map[string]vulnerability.Job
	numManaged  uint
	maxJobs     uint
	maxReadTime time.Duration
}

// VulnJobManagerOptions are optional configuration parameters for VulnJobManager.
type VulnJobManagerOptions struct {
	MaxJobs     uint
	ReadTimeout time.Duration
}

// NewVulnJobManager constructs a new VulnJobManager.
func NewVulnJobManager(opts VulnJobManagerOptions) VulnJobManager {
	opts.applyDefaults()
	return VulnJobManager{
		managing:    make(map[string]vulnerability.Job),
		numManaged:  0,
		maxJobs:     opts.MaxJobs,
		maxReadTime: opts.ReadTimeout,
	}
}

// Register attempts to add a new job to the manager, returning an ID that
// must be provided during lookups.
func (jobs *VulnJobManager) Register(job vulnerability.Job) (string, error) {
	if jobs.numManaged >= jobs.maxJobs {
		return "", fmt.Errorf("job queue full; try again later")
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
func (jobs *VulnJobManager) Retrieve(jobID string) (
	[]vulnerability.Vulnerability,
	[]error,
	complete,
) {
	job, found := jobs.managing[jobID]
	vulns := []vulnerability.Vulnerability{}
	errs := []error{}
	fin := complete(false)

	if !found {
		return []vulnerability.Vulnerability{}, []error{fmt.Errorf(errNoSuchJob)}, fin
	}

	stopAt := time.Now().Add(jobs.maxReadTime)

readUntilTimeout:
	for {
		timeLeft := time.Until(stopAt)
		select {
		case <-time.After(timeLeft):
			break readUntilTimeout

		case <-job.Finished:
			delete(jobs.managing, jobID)
			jobs.numManaged--
			fin = complete(true)
			break readUntilTimeout

		case err := <-job.Errors:
			errs = append(errs, err)

		case vuln := <-job.Vulns:
			vulns = append(vulns, vuln)
		}
	}

	return vulns, errs, fin
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
