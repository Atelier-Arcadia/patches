package main

import (
	"net/http"
	"testing"

	"github.com/arcrose/patches/pkg/pack"
	"github.com/arcrose/patches/pkg/vulnerability"
)

const testVuln = vulnerability.Vulnerability{
	Name:                 "testvuln",
	AffectedPackageName:  "testpackage",
	AffectedPlatformName: "debian-8",
	DetailsHref:          "http://test.com",
	SeverityRating:       vulnerability.SevLow,
	FixedInPackages: []pack.Package{
		{
			Name:    "testpackage",
			Version: "1.2.3",
		},
	},
}

func TestReportVulnsToAPI(t *testing.T) {
	testCases := []struct {
		Description    string
		VulnsToSend    uint
		Handler        http.HandlerFunc
		ExpectedErrors uint
	}{
		{
			Description:    "Should send all vulnerabilities to the API",
			VulnsToSend:    4,
			Handler:        count(4),
			ExpectedErrors: 0,
		},
		{
			Description:    "Should report as many errors as failures occur reporting to the API",
			VulnsToSend:    3,
			Handler:        fail,
			ExpectedErrors: 3,
		},
	}

	for caseNum, testCase := range testCases {
		t.Logf("Running TestReportVulnsToAPI case #%d: %s", caseNum, testCase)

		func() {
			server := httptest.NewServer(testCase.Handler)
			defer server.Close()

			terminate := make(chan bool, 1)
			confirm := make(chan bool, 1)

			vulns, errs := __reportVulnsToAPI(server.URL, terminate, confirm)

			var i uint
			for i = 0; i < testCase.VulnsToSend; i++ {
				vulns <- testVuln
			}

			var errsCounted uint = 0
		counter:
			for {
				select {
				case err := <-errs:
					errsCounted++

				case <-time.After(1 * time.Second):
					break counter
				}
			}

			if errsCounted != testCase.ExpectedErrors {
				t.Errorf("Expected %d errors but only got %d", testCase.ExpectedErrors, errsCounted)
			}
		}()
	}
}

func TestReport(t *testing.T) {
	testCases := []struct {
		Description string
		Handler     http.HandlerFunc
		ExpectError bool
	}{
		{
			Description: "Should send serialized vulnerability info to a RESTful API",
			Handler:     validate,
			ExpectError: false,
		},
		{
			Description: "Should report an error if the request to the API fails",
			Handler:     fail,
			ExpectError: true,
		},
	}

	for caseNum, testCase := range testCases {
		t.Logf("Running TestReport case #%d: %s", caseNum, testCase.Description)

		func() {
			server := httptest.NewServer(testCase.Handler)
			defer server.Close()

			errs := make(chan error, 1)
			__report(server.URL, testVuln, errs)

			select {
			case err := <-errs:
				if !testCase.ExpectError {
					t.Errorf("Did not expect to get an error but got '%s'", err.Error())
				}

			default:
				if testCase.ExpectError {
					t.Errorf("Expected to get an error but did not")
				}
			}
		}()
	}
}

func validate(res http.ResponseWriter, req *http.Request) {
	decoded := vulnerability.Vulnerability{}
	decoder := json.NewDecoder(req.Body)
	defer req.Body.Close()

	decodeErr := decoder.Decode(&decoded)
	if decodeErr != nil {
		http.WriteHeader(http.StatusBadRequest)
		res.Write([]byte("fail"))
		return
	}

	if !decoded.Equals(testVuln) {
		http.WriteHeader(http.StatusBadRequest)
		res.Write([]byte("fail"))
		return
	}

	res.Write([]byte("success"))
}

func count(expectdVulns uint) http.HandlerFunc {
	vulnsReceived := 0

	return func(res http.ResponseWriter, req *http.Request) {
		if vulnsReceived > expectdVulns {
			res.WriteHeader(http.StatusNotAcceptable)
			res.Write([]byte("fail"))
			return
		}

		vulnsReceived++
		res.Write([]byte("success"))
	}
}

func fail(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusInternalServerError)
	res.Write([]byte("fail"))
}
