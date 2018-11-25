package clients

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/arcrose/patches/pkg/pack"
	"github.com/arcrose/patches/pkg/platform"
	"github.com/arcrose/patches/pkg/vulnerability"

	"github.com/arcrose/patches/internal/limit"
)

type response struct {
	Error           *string                       `json:"error"`
	RequestID       string                        `json:"requestID"`
	Finished        bool                          `json:"finished"`
	Vulnerabilities []vulnerability.Vulnerability `json:"vulns"`
}

func TestClairClientVulnerabilities(t *testing.T) {
	testCases := []struct {
		Description    string
		PlatformName   string
		RequestHandler http.HandlerFunc
		ExpectedVulns  []vulnerability.Vulnerability
		ExpectError    bool
	}{
		{
			Description:    "Should retrieve all vulnerabilities returned by the server",
			PlatformName:   "debian-8",
			RequestHandler: serveVulns(2),
			ExpectError:    false,
			ExpectedVulns: []vulnerability.Vulnerability{
				{
					Name:                 "testvuln",
					AffectedPackageName:  "testpackage",
					AffectedPlatformName: "debian-8",
					DetailsHref:          "link",
					SeverityRating:       vulnerability.SeverityLow,
					FixedInPackages: []pack.Package{
						{
							Name:    "testpackage",
							Version: "1.2.3",
						},
					},
				},
				{
					Name:                 "testvuln",
					AffectedPackageName:  "testpackage",
					AffectedPlatformName: "debian-8",
					DetailsHref:          "link",
					SeverityRating:       vulnerability.SeverityLow,
					FixedInPackages: []pack.Package{
						{
							Name:    "testpackage",
							Version: "1.2.3",
						},
					},
				},
			},
		},
		{
			Description:    "Should return an error if the server returns one",
			PlatformName:   "debian-8",
			RequestHandler: serveError,
			ExpectError:    true,
			ExpectedVulns:  []vulnerability.Vulnerability{},
		},
	}

	for caseNum, testCase := range testCases {
		t.Logf("Running TestClient case %d: %s", caseNum, testCase.Description)

		func() {
			server := httptest.NewServer(testCase.RequestHandler)
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)
			serverPort, _ := strconv.ParseUint(serverURL.Port(), 10, 16)

			limiter := limit.ConstantRateLimiter(10 * time.Millisecond)
			client := NewClairClient(
				"http://"+serverURL.Hostname(),
				uint16(serverPort),
				limiter)

			vulns, fin, errs := client.Vulnerabilities(platform.Debian8)
			var err error
			allVulns := []vulnerability.Vulnerability{}

		readall:
			for {
				select {
				case v := <-vulns:
					allVulns = append(allVulns, v)

				case <-fin:
					break readall

				case e := <-errs:
					err = e
				}
			}

			gotErr := err != nil
			if gotErr && !testCase.ExpectError {
				t.Errorf("Did not expect an error but got '%s'", err.Error())
			} else if !gotErr && testCase.ExpectError {
				t.Errorf("Expected an error but did not get one")
			}

			for _, expected := range testCase.ExpectedVulns {
				wasFound := false
				for _, found := range allVulns {
					if found.Equals(expected) {
						wasFound = true
						break
					}
				}
				if !wasFound {
					t.Errorf("Did not find vulnerability: %s", expected.String())
				}
			}
		}()
	}
}

func serveVulns(num uint) http.HandlerFunc {
	var served uint = 0

	return func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")

		if served >= num {
			res.WriteHeader(http.StatusInternalServerError)
			res.Write([]byte(`{
        "error": "no more vulnerabilies to serve",
        "requestID": "",
        "finished": false,
        "vulns": []
      }`))
			return
		}

		qs := req.URL.Query()
		platforms, found1 := qs["platform"]
		requestIDs, found2 := qs["requestID"]
		errMsg := ""
		if !found1 || len(platforms) == 0 {
			errMsg = "missing field platform"
		}
		if served > 0 && (!found2 || len(requestIDs) == 0) {
			errMsg = "missing field requestID"
		}

		if errMsg != "" {
			res.WriteHeader(http.StatusBadRequest)
			res.Write([]byte(fmt.Sprintf(`{
        "error": "%s",
        "requestID": "",
        "finished": false,
        "vulns": []
      }`, errMsg)))
			return
		}

		served++
		finished := served == num
		res.Write([]byte(fmt.Sprintf(`{
      "error": null,
      "requestID": "testid",
      "finished": %v,
      "vulns": [
        {
          "name": "testvuln",
          "affectedPackageName": "testpackage",
          "affectedPlatform": "debian-8",
          "detailsHref": "link",
          "severityRating": 2,
          "fixedInPackages": [
            {
              "name": "testpackage",
              "version": "1.2.3"
            }
          ]
        }
      ]
    }`, finished)))
	}
}

func serveError(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusBadRequest)
	res.Header().Set("Content-Type", "application/json")
	res.Write([]byte(`{
    "error": "testerror",
    "requestID": "",
    "vulns": []
  }`))
}
