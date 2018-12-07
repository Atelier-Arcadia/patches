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
	VulnsPerRequest  uint
	RequestsToHandle uint
	ErrorMessage     string
}

func TestClairVulnServer(t *testing.T) {
	testErr := "testerror"
	testCases := []struct {
		Description       string
		VulnSource        vulnerability.Source
		ExpectedResponses []response
		ExpectError       bool
	}{
		{
			Description: "Should serve requests for vulnerabilities for a platform",
			VulnSource: mockSource{
				VulnsPerRequest:  2,
				RequestsToHandle: 1,
			},
			ExpectError: false,
			ExpectedResponses: []response{
				{
					Error:     nil,
					RequestID: "testid",
					Finished:  false,
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
			},
		},
		{
			Description: "Should handle multiple requests fetching remaining vulnerabilities",
			VulnSource: mockSource{
				VulnsPerRequest:  1,
				RequestsToHandle: 2,
			},
			ExpectError: false,
			ExpectedResponses: []response{
				{
					Error:     nil,
					RequestID: "testid",
					Finished:  false,
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
					},
				},
				{
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
					},
				},
			},
		},
		{
			Description: "Should serve an error if clair errors",
			VulnSource: mockSource{
				ErrorMessage: testErr,
			},
			ExpectError: true,
			ExpectedResponses: []response{
				{
					Error:           &testErr,
					RequestID:       "testid",
					Finished:        false,
					Vulnerabilities: []vulnerability.Vulnerability{},
				},
			},
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

			var requestID *string = nil

			resp, err := requestVulns(server.URL, requestID)
			requestNum := 0

			if err != nil {
				t.Fatal(err)
			}

			for !resp.Finished {
				if requestID == nil {
					*requestID = resp.RequestID
				} else if *requestID != resp.RequestID {
					t.Errorf("Should get the same requestID every time")
				}

				gotErr := resp.Error != nil
				if gotErr && !testCase.ExpectError {
					t.Fatalf("Did not expect an error but got '%s'", *resp.Error)
				} else if !gotErr && testCase.ExpectError {
					t.Fatalf("Expected to get an error, but did not get one")
				}

				if resp.Finished != testCase.ExpectedResponses[requestNum].Finished {
					t.Errorf(
						"Expected finished to be %v but it's %v",
						testCase.ExpectedResponses[requestNum].Finished,
						resp.Finished)
				}

				for _, vuln := range testCase.ExpectedResponses[requestNum].Vulnerabilities {
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

				resp, err = requestVulns(server.URL, requestID)
				requestNum++
			}
		}()
	}
}

func requestVulns(serverURL string, requestID *string) (response, error) {
	url := ""
	if requestID == nil {
		url = serverURL + "/vulns?platform=debian-8"
	} else {
		url = serverURL + "/vulns?platform=debian-8&requestID=" + *requestID
	}
	res, err := http.Get(url)
	if err != nil {
		return response{}, err
	}
	defer res.Body.Close()

	decoder := json.NewDecoder(res.Body)
	resp := response{}
	decodeErr := decoder.Decode(&resp)
	if decodeErr != nil {
		return response{}, decodeErr
	}
	return resp, nil
}

func (mock mockSource) Vulnerabilities(_ platform.Platform) vulnerability.Job {
	job := vulnerability.Job{
		Vulns:    make(chan vulnerability.Vulnerability),
		Finished: make(chan done.Done, 1),
		Errors:   make(chan error, 1),
	}

	if mock.VulnsPerRequest == 0 {
		job.Errors <- fmt.Errorf("%s", mock.ErrorMessage)
		job.Finished <- done.Done{}
		return job
	}

	go func() {
		vulnsToServe := mock.VulnsPerRequest * mock.RequestsToHandle

		var i uint
		for i = 0; i < vulnsToServe; i++ {
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
