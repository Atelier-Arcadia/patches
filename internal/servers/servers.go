package servers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/zsck/patches/pkg/platform"
	"github.com/zsck/patches/pkg/vulnerability"
)

type ClairVulnServer struct {
	vulnSource vulnerability.Source
}

type vulnsResponse struct {
	Error           *string                       `json:"error"`
	RequestID       string                        `json:"requestID"`
	Vulnerabilities []vulnerability.Vulnerability `json:"vulns"`
}

func NewClairVulnServer(source vulnerability.Source) ClairVulnServer {
	return ClairVulnServer{
		vulnSource: source,
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

	requestID, found := qs["requestID"]
	var vulns []vulnerability.Vulnerability
	var err error
	if found {
		vulns, err = server.__runJob(requestID, pform)
	} else {
		requestID, vulns, err = server.__newJob(pform)
	}

	if err != nil {
		http.WriteHeaer(http.StatusBadRequest)
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
