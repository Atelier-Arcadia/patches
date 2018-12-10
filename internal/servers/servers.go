package servers

import (
	"encoding/json"
	"net/http"

	log "github.com/Sirupsen/logrus"

	"github.com/arcrose/patches/pkg/platform"
	"github.com/arcrose/patches/pkg/vulnerability"
)

var errMissingPlatform = "missing query parameter 'platform'"
var errNoSuchPlatform = "no such platform"

// ClairVulnServer is an HTTP server that serves requests for vulnerabilities affecting
// a specified platform.
type ClairVulnServer struct {
	source vulnerability.Source
	jobs   VulnJobManager
}

type vulnsResponse struct {
	Error           *string                       `json:"error"`
	RequestID       string                        `json:"requestID"`
	Finished        complete                      `json:"finished"`
	Vulnerabilities []vulnerability.Vulnerability `json:"vulns"`
}

// NewClairVulnServer constructs a new ClairVulnServer.
func NewClairVulnServer(
	source vulnerability.Source,
	opts VulnJobManagerOptions,
) ClairVulnServer {
	return ClairVulnServer{
		source: source,
		jobs:   NewVulnJobManager(opts),
	}
}

func (server ClairVulnServer) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	log.Infof("%s %s", req.Method, req.URL.String())

	res.Header().Set("Content-Type", "application/json")
	response := json.NewEncoder(res)

	qs := req.URL.Query()
	platforms, found := qs["platform"]
	if !found || len(platforms) == 0 {
		res.WriteHeader(http.StatusBadRequest)
		response.Encode(vulnsResponse{
			Error: &errMissingPlatform,
		})
		return
	}

	pform, found := platform.Translate(platforms[0])
	if !found {
		res.WriteHeader(http.StatusBadRequest)
		response.Encode(vulnsResponse{
			Error: &errNoSuchPlatform,
		})
		return
	}

	requestIDs, found := qs["requestID"]
	var requestID string
	var vulns []vulnerability.Vulnerability
	var errs []error
	var fin complete = complete(false)

	if found && len(requestIDs) > 0 {
		requestID = requestIDs[0]
		vulns, errs, fin = server.__runJob(requestID)
	} else {
		requestID, vulns, errs, fin = server.__newJob(pform)
	}

	for _, err := range errs {
		log.Errorf("In request for %s, got error '%s'", req.URL.String(), err.Error())
	}

	response.Encode(vulnsResponse{
		Vulnerabilities: vulns,
		RequestID:       requestID,
		Finished:        fin,
	})
}

func (server ClairVulnServer) __runJob(id string) (
	[]vulnerability.Vulnerability,
	[]error,
	complete,
) {
	vulns, errs, fin := server.jobs.Retrieve(id)
	return vulns, errs, fin
}

func (server ClairVulnServer) __newJob(pform platform.Platform) (
	string,
	[]vulnerability.Vulnerability,
	[]error,
	complete,
) {
	job := server.source.Vulnerabilities(pform)

	jobID, err := server.jobs.Register(job)
	if err != nil {
		return "", []vulnerability.Vulnerability{}, []error{err}, complete(false)
	}

	foundVulns, encounteredErrs, fin := server.jobs.Retrieve(jobID)
	return jobID, foundVulns, encounteredErrs, fin
}
