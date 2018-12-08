package servers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

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

func TestClairVulnServerInputValidation(t *testing.T) {
	testCases := []struct {
		Description       string
		PlatformName      string
		VulnSource        vulnerability.Source
		UseRetrievedJobID bool
		ExpectedResponses []response
	}{
		{
			Description:  "Should accept a valid platform",
			PlatformName: "debian-8",
			VulnSource: mockSource{
				VulnsPerRequest:  1,
				RequestsToHandle: 2,
			},
			UseRetrievedJobID: true,
			ExpectedResponses: []response{
				{
					Error:    nil,
					Finished: false,
				},
				{
					Error:    nil,
					Finished: true,
				},
			},
		},
		{
			Description:       "Should error if the platform parameter is missing",
			PlatformName:      "",
			VulnSource:        mockSource{},
			UseRetrievedJobID: false,
			ExpectedResponses: []response{
				{
					Error:    &errMissingPlatform,
					Finished: false,
				},
				{
					Error:    &errMissingPlatform,
					Finished: false,
				},
			},
		},
		{
			Description:       "Should error if the platform is unsupported",
			PlatformName:      "not-supported",
			VulnSource:        mockSource{},
			UseRetrievedJobID: false,
			ExpectedResponses: []response{
				{
					Error:    &errNoSuchPlatform,
					Finished: false,
				},
				{
					Error:    &errNoSuchPlatform,
					Finished: false,
				},
			},
		},
		{
			Description:  "Should accept a valid platform and known job ID",
			PlatformName: "debian-8",
			VulnSource: mockSource{
				VulnsPerRequest:  1,
				RequestsToHandle: 2,
			},
			UseRetrievedJobID: true,
			ExpectedResponses: []response{
				{
					Error:    nil,
					Finished: false,
				},
				{
					Error:    nil,
					Finished: true,
				},
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
				testCase.VulnSource,
				VulnJobManagerOptions{}))
			defer server.Close()

			// Make a first request to kick off a job.
			url := server.URL + "/vulns"
			if testCase.PlatformName != "" {
				url = fmt.Sprintf("%s?platform=%s", url, testCase.PlatformName)
			}

			resp, err := requestVulns(url)
			if err != nil {
				t.Fatal(err)
			}

			if resp.Error != testCase.ExpectedResponses[0].Error {
				t.Errorf(
					"Expected to get error %v but got %v",
					testCase.ExpectedResponses[0].Error,
					resp.Error)
			}
			if resp.Finished != testCase.ExpectedResponses[0].Finished {
				t.Errorf(
					"Expected 'finished' to be %v but it's %v",
					testCase.ExpectedResponses[0].Finished,
					resp.Finished)
			}

			// Make a second request to make sure the requestID is handled correctly
			if testCase.UseRetrievedJobID {
				url = fmt.Sprintf("%s&requestID=%s", url, resp.RequestID)
			} else {
				url = fmt.Sprintf("%s&requestID=badid", url)
			}

			resp, err = requestVulns(url)
			if err != nil {
				t.Fatal(err)
			}

			if resp.Error != testCase.ExpectedResponses[0].Error {
				t.Errorf(
					"Expected to get error %v but got %v",
					testCase.ExpectedResponses[0].Error,
					resp.Error)
			}
			if resp.Finished != testCase.ExpectedResponses[0].Finished {
				t.Errorf(
					"Expected 'finished' to be %v but it's %v",
					testCase.ExpectedResponses[0].Finished,
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
		ExpectedResponses []response
	}{
		{
			Description: "Should serve all vulns when the right job ID is sent",
			VulnSource: mockSource{
				VulnsPerRequest:  1,
				RequestsToHandle: 2,
			},
			UseRetrievedJobID: true,
			ExpectedResponses: []response{
				{
					Error:           nil,
					Finished:        false,
					Vulnerabilities: []vulnerability.Vulnerability{testVuln},
				},
				{
					Error:           nil,
					Finished:        true,
					Vulnerabilities: []vulnerability.Vulnerability{testVuln},
				},
			},
		},
		{
			Description: "Should serve an error if the vuln stream errors",
			VulnSource: mockSource{
				ReturnError: true,
			},
			UseRetrievedJobID: true,
			ExpectedResponses: []response{
				{
					Error: &testError,
				},
			},
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
		Finished: make(chan done.Done, 1),
		Errors:   make(chan error),
	}

	if mock.ReturnError {
		go func() {
			var i uint
			for i = 0; i < mock.RequestsToHandle; i++ {
				job.Errors <- errors.New(testError)
			}
			job.Finished <- done.Done{}
		}()
	} else {
		go func() {
			vulnsToServe := mock.VulnsPerRequest * mock.RequestsToHandle

			var i uint
			for i = 0; i < vulnsToServe; i++ {
				job.Vulns <- testVuln
			}
			job.Finished <- done.Done{}
		}()
	}

	return job
}
