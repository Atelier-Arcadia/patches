package servers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/zsck/patches/pkg/platform"
	"github.com/zsck/patches/pkg/vulnerability"
)

type ClairVulnServer struct {
	source vulnerability.Source
	jobs   VulnJobManager
}

type vulnsResponse struct {
	Error           *string                       `json:"error"`
	RequestID       string                        `json:"requestID"`
	Vulnerabilities []vulnerability.Vulnerability `json:"vulns"`
}

func NewClairVulnServer(source vulnerability.Source, opts VulnJobManagerOptions) ClairVulnServer {
	return ClairVulnServer{
		source: source,
		jobs:   NewVulnJobManager(opts),
	}
}

func translatePlatform(name string) (platform.Platform, bool) {
	supported := map[string]platform.Platform{
		"debian 8": platform.Debian8,
	}

	pform, found := supported[name]
	if !found {
		return platform.Platform{}, false
	}

	return pform, true
}

func (server ClairVulnServer) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	response := json.NewEncoder(res)

	qs := req.URL.Query()
	platforms, found := qs["platform"]
	if !found || len(platforms) == 0 {
		res.WriteHeader(http.StatusBadRequest)
		errMsg := "missing query parameter 'platform'"

		response.Encode(vulnsResponse{
			Error: &errMsg,
		})
		return
	}

	pform, found := translatePlatform(platforms[0])
	if !found {
		res.WriteHeader(http.StatusBadRequest)
		errMsg := fmt.Sprintf("no such platform '%s'", platforms[0])

		response.Encode(vulnsResponse{
			Error: &errMsg,
		})
		return
	}

	requestIDs, found := qs["requestID"]
	var requestID string
	var vulns []vulnerability.Vulnerability
	var errs []error
	if found {
		requestID = requestIDs[0]
		vulns, errs = server.__runJob(requestID)
	} else {
		requestID, vulns, errs = server.__newJob(pform)
	}

	if len(errs) > 0 {
		res.WriteHeader(http.StatusBadRequest)
		errMsg := "invalid request id"

		response.Encode(vulnsResponse{
			Error: &errMsg,
		})
		return
	}

	response.Encode(vulnsResponse{
		Vulnerabilities: vulns,
		RequestID:       requestID,
	})
}

func (server ClairVulnServer) __runJob(id string) ([]vulnerability.Vulnerability, []error) {
	vulns, errs := server.jobs.Retrieve(id)
	return vulns, errs
}

func (server ClairVulnServer) __newJob(pform platform.Platform) (
	string,
	[]vulnerability.Vulnerability,
	[]error,
) {
	vulns, finished, errs := server.source.Vulnerabilities(pform)
	jobID, err := server.jobs.Register(NewFetchVulnsJob(vulns, finished, errs))
	if err != nil {
		return "", []vulnerability.Vulnerability{}, []error{err}
	}

	foundVulns, encounteredErrs := server.jobs.Retrieve(jobID)
	return jobID, foundVulns, encounteredErrs
}
