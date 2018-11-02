package clair

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSummarizeVulnerabilities(t *testing.T) {
	testCases := []struct {
		Description       string
		RequestHandler    http.HandlerFunc
		TargetPlatform    Platform
		ExpectedSummaries []summary
		ExpectError       bool
	}{
		{
			Description:    "The client should return the summaries written by the API",
			RequestHandler: serveSummaries,
			TargetPlatform: Debian8,
			ExpectedSummaries: []summary{
				{Name: "testvuln1"},
				{Name: "testvuln2"},
			},
			ExpectError: false,
		},
		{
			Description:       "The client should return an error when the API writes one",
			RequestHandler:    serveError,
			TargetPlatform:    Debian8,
			ExpectedSummaries: []summary{},
			ExpectError:       true,
		},
		{
			Description:       "The client should return an error when the request is bad",
			RequestHandler:    serveBadRequest,
			TargetPlatform:    Debian8,
			ExpectedSummaries: []summary{},
			ExpectError:       true,
		},
	}

	for caseNum, testCase := range testCases {
		t.Logf("Running TestSummarizeVulnerabiltiies case #%d: %s", caseNum, testCase.Description)

		func() {
			server := httptest.NewServer(testCase.RequestHandler)
			defer server.Close()

			config := Clair{
				BaseURL: server.URL,
			}
			vulns, err := summarizeVulnerabilities(config, testCase.TargetPlatform)

			gotErr := err != nil
			if gotErr && !testCase.ExpectError {
				t.Errorf("Did not expect an error, but got '%s'", err.Error())
			} else if !gotErr && testCase.ExpectError {
				t.Errorf("Expected an error but did not get one")
			}

			if len(vulns) != len(testCase.ExpectedSummaries) {
				t.Fatalf("Expected to get %d vulns but got %d", len(testCase.ExpectedSummaries), len(vulns))
			}

			for i := range testCase.ExpectedSummaries {
				found := false
				for j := range vulns {
					if vulns[i] == testCase.ExpectedSummaries[j] {
						found = true
						break
					}
				}
			}

			if !found {
				t.Errorf("Did not find all of the vulnerabilities expected")
			}
		}()
	}
}

func serveSummaries(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	res.Write([]byte(`
{
  "Vulnerabilities": [
    {
      "Name": "testvuln1"
    },
    {
      "Name": "testvuln2"
    }
  ]
}
  `))
}

func serveFixedVulnDescription(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	res.Write([]byte(`
{
  "Vulnerability": {
    "Name": "testvulnfull",
    "Link": "address.website",
    "Severity": "Low",
    "FixedIn": [
      {
        "Name": "fix1",
        "Version": "1.2.3"
      },
      {
        "Name": "fix2",
        "Version": "3.2.1"
      }
    ]
  }
}
  `))
}

func serveUnfixedVulnDescription(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	res.Write([]byte(`
{
  "Vulnerability": {
    "Name": "testvulnunfixed",
    "Link": "address.othersite",
    "Severity": "High"
  }
}
  `))
}

func serveError(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	res.Write([]byte(`
{
  "Error": {
    "Message": "testerror"
  }
}
  `))
}

func serveBadRequest(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusBadRequest)
}
