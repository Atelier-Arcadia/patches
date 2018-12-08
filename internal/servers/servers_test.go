package servers

import (
	"encoding/json"
	"errors"
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

var testError = "testerror"

var testVuln = vulnerability.Vulnerability{
	Name:                 "testvuln",
	AffectedPackageName:  "testpackage",
	AffectedPlatformName: "debian-8",
	DetailsHref:          "website.com",
	SeverityRating:       vulnerability.SeverityLow,
	FixedInPackages: []pack.Package{
		{
			Name:    "testpackage",
			Version: "1.2.3",
		},
	},
}

var requestTimeout = 10 * time.Millisecond

type response struct {
	Error           *string                       `json:"error"`
	RequestID       string                        `json:"requestID"`
	Finished        bool                          `json:"finished"`
	Vulnerabilities []vulnerability.Vulnerability `json:"vulns"`
}

type mockSource struct {
	VulnsPerRequest  uint
	RequestsToHandle uint
	ReturnError      bool
}

type nilSource struct{}

func TestClairVulnServerInputValidation(t *testing.T) {
	testCases := []struct {
		Description       string
		PlatformName      string
		UseRetrievedJobID bool
		ExpectedResponse  response
	}{
		{
			Description:       "Should accept a valid platform",
			PlatformName:      "debian-8",
			UseRetrievedJobID: true,
			ExpectedResponse: response{
				Error:    nil,
				Finished: true,
			},
		},
		{
			Description:       "Should error if the platform parameter is missing",
			PlatformName:      "",
			UseRetrievedJobID: false,
			ExpectedResponse: response{
				Error:    &errMissingPlatform,
				Finished: false,
			},
		},
		{
			Description:       "Should error if the platform is unsupported",
			PlatformName:      "not-supported",
			UseRetrievedJobID: false,
			ExpectedResponse: response{
				Error:    &errNoSuchPlatform,
				Finished: false,
			},
		},
		{
			Description:       "Should accept a valid platform and known job ID",
			PlatformName:      "debian-8",
			UseRetrievedJobID: true,
			ExpectedResponse: response{
				Error:    nil,
				Finished: true,
			},
		},
	}

	for caseNum, testCase := range testCases {
		t.Logf(
			"Running TestClairVulnServerInputValidation case #%d: %s",
			caseNum,
			testCase.Description)

		func() {
			server := httptest.NewServer(NewClairVulnServer(
				nilSource{},
				VulnJobManagerOptions{}))
			defer server.Close()

			url := server.URL + "/vulns"
			if testCase.PlatformName != "" {
				url = fmt.Sprintf("%s?platform=%s", url, testCase.PlatformName)
			}

			resp, err := requestVulns(url)
			if err != nil {
				t.Fatal(err)
			}

			neitherNil := resp.Error != nil && testCase.ExpectedResponse.Error != nil
			if neitherNil && *resp.Error != *testCase.ExpectedResponse.Error {
				t.Errorf(
					"Expected to get error %v but got %v",
					testCase.ExpectedResponse.Error,
					resp.Error)
			}
			if resp.Finished != testCase.ExpectedResponse.Finished {
				t.Errorf(
					"Expected 'finished' to be %v but it's %v",
					testCase.ExpectedResponse.Finished,
					resp.Finished)
			}
		}()
	}
}

func TestClairVulnServerVulnServing(t *testing.T) {
	testCases := []struct {
		Description       string
		VulnSource        vulnerability.Source
		UseRetrievedJobID bool
		ExpectError       bool
	}{
		{
			Description: "Should serve vulns until the stream finishes",
			VulnSource: mockSource{
				VulnsPerRequest:  1,
				RequestsToHandle: 2,
			},
			UseRetrievedJobID: true,
			ExpectError:       false,
		},
		{
			Description: "Should serve an error if the vuln stream errors",
			VulnSource: mockSource{
				ReturnError:      true,
				RequestsToHandle: 1,
			},
			UseRetrievedJobID: true,
			ExpectError:       true,
		},
	}

	for caseNum, testCase := range testCases {
		t.Logf(
			"Running TestClairVulnServerVulnServing case #%d: %s",
			caseNum,
			testCase.Description)

		func() {
			server := httptest.NewServer(NewClairVulnServer(
				testCase.VulnSource,
				VulnJobManagerOptions{}))
			defer server.Close()

			url := server.URL + "/vulns?platform=debian-8"

			resp, err := requestVulns(url)
			if err != nil {
				t.Fatal(err)
			}

			gotErr := resp.Error != nil
			if gotErr && !testCase.ExpectError {
				t.Errorf("Did not expect an error, but got '%s'", *resp.Error)
			} else if !gotErr && testCase.ExpectError {
				t.Errorf("Expected to get an error but did not get one")
			}

			if testCase.UseRetrievedJobID {
				url = fmt.Sprintf("%s&requestID=%s", url, resp.RequestID)
			} else {
				url = fmt.Sprintf("%s&requestID=badid", url)
			}

			var requestsMade uint = 0
			for !resp.Finished {
				resp, err = requestVulns(url)
				requestsMade++
				if err != nil {
					t.Fatal(err)
				}

				gotErr := resp.Error != nil
				if gotErr && !testCase.ExpectError {
					t.Errorf("Did not expect an error, but got '%s'", *resp.Error)
				} else if !gotErr && testCase.ExpectError {
					t.Errorf("Expected to get an error but did not get one")
				}

				if testCase.ExpectError {
					return
				}

				if requestsMade > testCase.VulnSource.(mockSource).RequestsToHandle+1 {
					t.Fatalf("Vuln stream should have finished after %d requests", requestsMade)
					return
				}
			}
		}()
	}
}

func TestClairVulnServerJobManagement(t *testing.T) {
	testCases := []struct {
		Description       string
		RequestsToMake    uint
		VulnSource        vulnerability.Source
		UseRetrievedJobID bool
		ExpectedResponses []response
	}{
		{
			Description:    "Should serve vulns until job finishes",
			RequestsToMake: 3,
			VulnSource: mockSource{
				VulnsPerRequest:  1,
				RequestsToHandle: 3,
			},
			UseRetrievedJobID: true,
			ExpectedResponses: []response{
				{
					Finished: false,
				},
				{
					Finished: false,
				},
				{
					Finished: true,
				},
			},
		},
		{
			Description:    "Should serve an error if a request is made for a finished job",
			RequestsToMake: 3,
			VulnSource: mockSource{
				VulnsPerRequest:  1,
				RequestsToHandle: 2,
			},
			UseRetrievedJobID: true,
			ExpectedResponses: []response{
				{
					Finished: false,
				},
				{
					Finished: true,
				},
				{
					Error:    &errNoSuchJob,
					Finished: false,
				},
			},
		},
		{
			Description:       "Should serve an error when a job that does not exist is requested",
			RequestsToMake:    2,
			VulnSource:        mockSource{},
			UseRetrievedJobID: false,
			ExpectedResponses: []response{
				{
					Finished: false,
				},
				{
					Error:    &errNoSuchJob,
					Finished: false,
				},
			},
		},
	}

	for caseNum, testCase := range testCases {
		t.Logf(
			"Running TestClairVulnServerJobManagement case #%d: %s",
			caseNum,
			testCase.Description)

		func() {
			server := httptest.NewServer(NewClairVulnServer(
				testCase.VulnSource,
				VulnJobManagerOptions{}))
			defer server.Close()
		}()
	}
}

func requestVulns(url string) (response, error) {
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
		Finished: make(chan done.Done),
		Errors:   make(chan error),
	}

	if mock.ReturnError {
		go func() {
			var i uint
			for i = 0; i < mock.RequestsToHandle; i++ {
				job.Errors <- errors.New(testError)
				<-time.After(requestTimeout)
			}
			job.Finished <- done.Done{}
		}()
	} else {
		go func() {
			vulnsToServe := mock.VulnsPerRequest * mock.RequestsToHandle

			var i, j uint
			for j = 0; j < mock.RequestsToHandle; j++ {
				for i = 0; i < vulnsToServe; i++ {
					job.Vulns <- testVuln
				}
				<-time.After(requestTimeout)
			}
			job.Finished <- done.Done{}
		}()
	}

	return job
}

func (mock nilSource) Vulnerabilities(_ platform.Platform) vulnerability.Job {
	job := vulnerability.Job{
		Vulns:    make(chan vulnerability.Vulnerability),
		Finished: make(chan done.Done, 1),
		Errors:   make(chan error),
	}

	job.Finished <- done.Done{}

	return job
}
