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

var testErr = "testerror"

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
			ExpectedResponse: []response{
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
		Errors:   make(chan error),
	}

	if mock.ReturnError {
		go func() {
			var i uint
			for i = 0; i < mock.RequestsToHandle; i++ {
				job.Errors <- testError
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
