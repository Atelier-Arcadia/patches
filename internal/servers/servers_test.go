package servers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/arcrose/patches/pkg/done"
	"github.com/arcrose/patches/pkg/pack"
	"github.com/arcrose/patches/pkg/platform"
	"github.com/arcrose/patches/pkg/vulnerability"
)

type response struct {
	Error           *string                       `json:"error"`
	RequestID       string                        `json:"requestID"`
	Finished        bool                          `json:"finished"`
	Vulnerabilities []vulnerability.Vulnerability `json:"vulns"`
}

type mockSource struct {
	NumToGenerate uint
	ErrorMessage  string
}

func TestClairVulnServer(t *testing.T) {
	testErr := "testerror"
	testCases := []struct {
		Description      string
		VulnSource       vulnerability.Source
		ExpectedResponse response
		ExpectError      bool
	}{
		{
			Description: "Should serve requests for vulnerabilities for a platform",
			VulnSource:  serveDebian8Vulns(2),
			ExpectedResponse: response{
				Error:     nil,
				RequestID: "testid",
				Finished:  true,
				Vulnerabilities: []vulnerability.Vulnerability{
					{
						Name:                 "testvuln1",
						AffectedPackageName:  "testpackage1",
						AffectedPlatformName: "debian-8",
						DetailsHref:          "website.com",
						SeverityRating:       vulnerability.SeverityLow,
						FixedInPackages: []pack.Package{
							{
								Name:    "testpackage1",
								Version: "3.2.1",
							},
						},
					},
					{
						Name:                 "testvuln2",
						AffectedPackageName:  "testpackage2",
						AffectedPlatformName: "debian-8",
						DetailsHref:          "website.com",
						SeverityRating:       vulnerability.SeverityLow,
						FixedInPackages: []pack.Package{
							{
								Name:    "testpackage2",
								Version: "3.2.1",
							},
						},
					},
				},
			},
			ExpectError: false,
		},
		{
			Description: "Should handle multiple requests fetching remaining vulnerabilities",
			VulnSource:  serveDebian8Vulns(1),
			ExpectedResponse: response{
				Error:     nil,
				RequestID: "testid",
				Finished:  true,
				Vulnerabilities: []vulnerability.Vulnerability{
					{
						Name:                 "testvuln1",
						AffectedPackageName:  "testpackage1",
						AffectedPlatformName: "debian-8",
						DetailsHref:          "website.com",
						SeverityRating:       vulnerability.SeverityLow,
						FixedInPackages: []pack.Package{
							{
								Name:    "testpackage1",
								Version: "3.2.1",
							},
						},
					},
					{
						Name:                 "testvuln1",
						AffectedPackageName:  "testpackage1",
						AffectedPlatformName: "debian-8",
						DetailsHref:          "website.com",
						SeverityRating:       vulnerability.SeverityLow,
						FixedInPackages: []pack.Package{
							{
								Name:    "testpackage1",
								Version: "3.2.1",
							},
						},
					},
				},
			},
			ExpectError: false,
		},
		{
			Description: "Should serve an error if clair errors",
			VulnSource:  serveError(testErr),
			ExpectedResponse: response{
				Error:           &testErr,
				RequestID:       "testid",
				Finished:        false,
				Vulnerabilities: []vulnerability.Vulnerability{},
			},
			ExpectError: true,
		},
	}

	for caseNum, testCase := range testCases {
		t.Logf("Running TestClairVulnServer case #%d: %s", caseNum, testCase.Description)

		func() {
			server := httptest.NewServer(
				NewClairVulnServer(testCase.VulnSource, VulnJobManagerOptions{
					ReadTimeout: 5 * time.Second,
				}))
			defer server.Close()

			url := server.URL + "/vulns?platform=debian-8"
			res, err := http.Get(url)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()

			decoder := json.NewDecoder(res.Body)
			resp := response{}
			decodeErr := decoder.Decode(&resp)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}

			//t.Logf("Got response: %v", resp)
			gotErr := resp.Error != nil
			if gotErr && !testCase.ExpectError {
				t.Fatalf("Did not expect an error but got '%s'", *resp.Error)
			} else if !gotErr && testCase.ExpectError {
				t.Fatalf("Expected to get an error, but did not get one")
			}

			if resp.Finished != testCase.ExpectedResponse.Finished {
				t.Errorf(
					"Expected finished to be %v but it's %v",
					testCase.ExpectedResponse.Finished,
					resp.Finished)
			}

			for _, vuln := range testCase.ExpectedResponse.Vulnerabilities {
				wasFound := false
				for _, found := range resp.Vulnerabilities {
					if vuln.Equals(found) {
						wasFound = true
						break
					}
				}
				if !wasFound {
					t.Errorf("Did not find vulnerability: %v", vuln)
				}
			}
		}()
	}
}

func serveDebian8Vulns(number uint) mockSource {
	return mockSource{
		NumToGenerate: number,
		ErrorMessage:  "",
	}
}

func serveError(errMsg string) mockSource {
	return mockSource{
		NumToGenerate: 0,
		ErrorMessage:  errMsg,
	}
}

func (mock mockSource) Vulnerabilities(_ platform.Platform) vulnerability.Job {
	job := vulnerability.Job{
		Vulns:    make(chan vulnerability.Vulnerability),
		Finished: make(chan done.Done, 1),
		Errors:   make(chan error, 1),
	}

	if mock.NumToGenerate == 0 {
		job.Errors <- fmt.Errorf("%s", mock.ErrorMessage)
		job.Finished <- done.Done{}
		return job
	}

	go func() {
		var i uint
		for i = 0; i < mock.NumToGenerate; i++ {
			vulnName := fmt.Sprintf("testvuln%d", i+1)
			pkgName := fmt.Sprintf("testpackage%d", i+1)

			job.Vulns <- vulnerability.Vulnerability{
				Name:                 vulnName,
				AffectedPackageName:  pkgName,
				AffectedPlatformName: "debian-8",
				DetailsHref:          "website.com",
				SeverityRating:       vulnerability.SeverityLow,
				FixedInPackages: []pack.Package{
					{
						Name:    pkgName,
						Version: "3.2.1",
					},
				},
			}
		}

		job.Finished <- done.Done{}
	}()

	return job
}
