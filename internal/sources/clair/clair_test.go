package clair

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zsck/patches/pkg/pack"
	"github.com/zsck/patches/pkg/vulnerability"
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
			RequestHandler: serveSummariesWithoutNextPage,
			TargetPlatform: Debian8,
			ExpectedSummaries: []summary{
				{Name: "testvuln1"},
				{Name: "testvuln2"},
			},
			ExpectError: false,
		},
		{
			Description:    "The client should make requests until it reads all pages",
			RequestHandler: serveSummariesWithNextPage(),
			TargetPlatform: Debian8,
			ExpectedSummaries: []summary{
				{Name: "testvuln1"},
				{Name: "testvuln2"},
				{Name: "testvuln3"},
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

			config := ClairAPIv1{
				BaseURL: server.URL,
			}
			vulnsChan, done, errs := summarizeVulnerabilities(config, testCase.TargetPlatform)

			vulns := []summary{}
		readall:
			for {
				select {
				case v := <-vulnsChan:
					vulns = append(vulns, v)

				case <-done:
					break readall

				case err := <-errs:
					if !testCase.ExpectError {
						t.Fatalf("Did not expect an error, but got '%s'", err.Error())
					}
					return
				}
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
				if !found {
					t.Errorf("Did not find: %v", testCase.ExpectedSummaries[i])
				}
			}
		}()
	}
}

func TestDescribeVulnerability(t *testing.T) {
	testCases := []struct {
		Description    string
		RequestHandler http.HandlerFunc
		VulnName       string
		TargetPlatform Platform
		ExpectedVuln   description
		ExpectError    bool
	}{
		{
			Description:    "The client should return valid data from the API",
			RequestHandler: serveFixedVulnDescription,
			VulnName:       "vuln1",
			TargetPlatform: Debian8,
			ExpectedVuln: description{
				Name:     "testvulnfull",
				Link:     "address.website",
				Severity: "Low",
				FixedIn: []fix{
					{
						Name:    "testpackage",
						Version: "1.2.3",
					},
					{
						Name:    "testpackage",
						Version: "3.2.1",
					},
				},
			},
			ExpectError: false,
		},
		{
			Description:    "The client should return an empty vulnerability if the vuln is not fixed",
			RequestHandler: serveUnfixedVulnDescription,
			VulnName:       "vuln2",
			TargetPlatform: Debian8,
			ExpectedVuln:   description{},
			ExpectError:    false,
		},
		{
			Description:    "The client should return an error when the API does",
			RequestHandler: serveError,
			VulnName:       "doesntmatter",
			TargetPlatform: Debian8,
			ExpectedVuln:   description{},
			ExpectError:    true,
		},
		{
			Description:    "The client should return an error when the request is bad",
			RequestHandler: serveBadRequest,
			VulnName:       "doesntmatter",
			TargetPlatform: Debian8,
			ExpectedVuln:   description{},
			ExpectError:    true,
		},
	}

	for caseNum, testCase := range testCases {
		t.Logf("Running TestDescribeVulnerability case #%d: %s", caseNum, testCase.Description)

		func() {
			server := httptest.NewServer(testCase.RequestHandler)
			defer server.Close()

			config := ClairAPIv1{
				BaseURL: server.URL,
			}
			vulnChan, done, errs := describeVulnerability(
				config,
				testCase.VulnName,
				testCase.TargetPlatform)

			for {
				select {
				case vuln := <-vulnChan:
					if !descriptionsEqual(testCase.ExpectedVuln, vuln) {
						t.Errorf(
							"Expected to get vulnerability %v but got %v",
							testCase.ExpectedVuln,
							vuln)
					}
					return

				case <-done:
					return

				case err := <-errs:
					if !testCase.ExpectError {
						t.Fatalf("Did not expect an error, but got '%s'", err.Error())
					}
					return
				}
			}
		}()
	}
}

func TestSourceImplementation(t *testing.T) {
	testCases := []struct {
		Description    string
		RequestHandler http.HandlerFunc
		TargetPlatform Platform
		ExpectError    bool
		ExpectedVulns  []vulnerability.Vulnerability
	}{
		{
			Description:    "Should serve all vulnerabilities from the Clair API",
			RequestHandler: clairRouter(serveSummariesWithNextPage(), serveFixedVulnDescription),
			TargetPlatform: Debian8,
			ExpectError:    false,
			ExpectedVulns: []vulnerability.Vulnerability{
				{
					Name:                 "testvulnfull",
					AffectedPackageName:  "testpackage",
					AffectedPlatformName: "debian:8",
					DetailsHref:          "address.website",
					SeverityRating:       vulnerability.SeverityLow,
					FixedInPackages: []pack.Package{
						{
							Name:    "testpackage",
							Version: "1.2.3",
						},
						{
							Name:    "testpackage",
							Version: "3.2.1",
						},
					},
				},
				{
					Name:                 "testvulnfull",
					AffectedPackageName:  "testpackage",
					AffectedPlatformName: "debian:8",
					DetailsHref:          "address.website",
					SeverityRating:       vulnerability.SeverityLow,
					FixedInPackages: []pack.Package{
						{
							Name:    "testpackage",
							Version: "1.2.3",
						},
						{
							Name:    "testpackage",
							Version: "3.2.1",
						},
					},
				},
				{
					Name:                 "testvulnfull",
					AffectedPackageName:  "testpackage",
					AffectedPlatformName: "debian:8",
					DetailsHref:          "address.website",
					SeverityRating:       vulnerability.SeverityLow,
					FixedInPackages: []pack.Package{
						{
							Name:    "testpackage",
							Version: "1.2.3",
						},
						{
							Name:    "testpackage",
							Version: "3.2.1",
						},
					},
				},
			},
		},
		/*
			{
				Description:    "Should not serve unpatched vulnerabilities",
				RequestHandler: clairRouter(serveSummariesWithoutNextPage, serveUnfixedVulnDescription),
				TargetPlatform: Debian8,
				ExpectError:    false,
				ExpectedVulns:  []vulnerability.Vulnerability{},
			},
			{
				Description:    "Should return errors from the API (case 1)",
				RequestHandler: clairRouter(serveError, serveUnfixedVulnDescription),
				TargetPlatform: Debian8,
				ExpectError:    true,
				ExpectedVulns:  []vulnerability.Vulnerability{},
			},
			{
				Description:    "Should return errors from the API (case 2)",
				RequestHandler: clairRouter(serveSummariesWithoutNextPage, serveError),
				TargetPlatform: Debian8,
				ExpectError:    true,
				ExpectedVulns:  []vulnerability.Vulnerability{},
			},
		*/
	}

	for caseNum, testCase := range testCases {
		t.Logf("Running TestSourceImplementation case #%d: %s", caseNum, testCase.Description)

		func() {
			server := httptest.NewServer(testCase.RequestHandler)
			defer server.Close()

			clair := ClairAPIv1{
				BaseURL: server.URL,
			}
			vulnChan, done, errs := NewStream(
				clair,
				testCase.TargetPlatform,
			).Vulnerabilities()

			vulns := []vulnerability.Vulnerability{}
		readall:
			for {
				select {
				case vuln := <-vulnChan:
					t.Logf("Got vuln: %v", vuln)
					vulns = append(vulns, vuln)

				case <-done:
					break readall

				case err := <-errs:
					if !testCase.ExpectError {
						t.Fatalf("Did not expect an error, but got '%s'", err.Error())
					}
					return
				}
			}

			for _, v1 := range testCase.ExpectedVulns {
				found := false
				for _, v2 := range vulns {
					if v1.Equals(v2) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Did not find expected vuln: %v", v1)
				}
			}
		}()
	}
}

func clairRouter(
	summaries http.HandlerFunc,
	descriptions http.HandlerFunc,
) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		if strings.Contains(req.URL.String(), "limit") {
			summaries(res, req)
		} else {
			descriptions(res, req)
		}
	}
}

func descriptionsEqual(d1, d2 description) bool {
	if len(d1.FixedIn) != len(d2.FixedIn) {
		return false
	}
	for _, f1 := range d1.FixedIn {
		found := false
		for _, f2 := range d2.FixedIn {
			if f1.Name == f2.Name && f1.Version == f2.Version {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return d1.Name == d2.Name &&
		d1.Link == d2.Link &&
		d1.Severity == d2.Severity
}

func serveSummariesWithoutNextPage(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")
	res.Write([]byte(`
{
  "Vulnerabilities": [
    {
      "Name": "testsingle1"
    },
    {
      "Name": "testsingle2"
    }
  ]
}
  `))
}

func serveSummariesWithNextPage() http.HandlerFunc {
	called := false

	return func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")
		withNext := `
{
  "Vulnerabilities": [
    {
      "Name": "testvuln1"
    },
    {
      "Name": "testvuln2"
    }
  ],
  "NextPage": "banana"
}
  `
		withoutNext := `
{
  "Vulnerabilities": [
    {
      "Name": "testvuln3"
    }
  ]
}
  `

		if !called {
			res.Write([]byte(withNext))
		} else {
			res.Write([]byte(withoutNext))
		}
		called = true
	}
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
        "Name": "testpackage",
        "Version": "1.2.3"
      },
      {
        "Name": "testpackage",
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
