package servers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zsck/patches/pkg/done"
	"github.com/zsck/patches/pkg/pack"
	"github.com/zsck/patches/pkg/platform"
	"github.com/zsck/patches/pkg/vulnerability"
)

type response struct {
	Error           *string                       `json:"error"`
	RequestID       string                        `json:"requestID"`
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
				Vulnerabilities: []vulnerability.Vulnerability{
					{
						Name:                 "testvuln1",
						AffectedPackageName:  "testpackage1",
						AffectedPlatformName: "debian 8",
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
						AffectedPlatformName: "debian 8",
						DetailsHref:          "website.com",
						SeverityRating:       vulnerability.SeverityLow,
						FixedInPackages: []pack.Package{
							{
								Name:    "testpackage2",
								Version: "1.2.3",
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
				Vulnerabilities: []vulnerability.Vulnerability{
					{
						Name:                 "testvuln1",
						AffectedPackageName:  "testpackage1",
						AffectedPlatformName: "debian 8",
						DetailsHref:          "website.com",
						SeverityRating:       vulnerability.SeverityLow,
						FixedInPackages: []pack.Package{
							{
								Name:    "testpackage",
								Version: "3.2.1",
							},
						},
					},
					{
						Name:                 "testvuln2",
						AffectedPackageName:  "testpackage2",
						AffectedPlatformName: "debian 8",
						DetailsHref:          "website.com",
						SeverityRating:       vulnerability.SeverityLow,
						FixedInPackages: []pack.Package{
							{
								Name:    "testpackage2",
								Version: "1.2.3",
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
				Vulnerabilities: []vulnerability.Vulnerability{},
			},
			ExpectError: true,
		},
	}

	for caseNum, testCase := range testCases {
		t.Logf("Running TestClairVulnServer case #%d: %s", caseNum, testCase.Description)

		func() {
			server := httptest.NewServer(
				NewClairVulnServer(testCase.VulnSource, VulnJobManagerOptions{}))
			defer server.Close()

			url := server.URL + "/vulns?platform=debian%208"
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

			gotErr := resp.Error != nil
			if gotErr && !testCase.ExpectError {
				t.Fatalf("Did not expect an error but got '%s'", *resp.Error)
			} else if !gotErr && testCase.ExpectError {
				t.Fatalf("Expected to get an error, but did not get one")
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

func (mock mockSource) Vulnerabilities(_ platform.Platform) (
	<-chan vulnerability.Vulnerability,
	<-chan done.Done,
	<-chan error,
) {
	vulns := make(chan vulnerability.Vulnerability)
	finished := make(chan done.Done)
	errs := make(chan error)

	if mock.NumToGenerate == 0 {
		errs <- fmt.Errorf("%s", mock.ErrorMessage)
		finished <- done.Done{}
		return vulns, finished, errs
	}

	var i uint
	for i = 0; i < mock.NumToGenerate; i++ {
		vulnName := fmt.Sprintf("testvuln%d", i+1)
		pkgName := fmt.Sprintf("testpackage%d", i+1)

		fmt.Printf("Writing vulnerability %s\n", vulnName)

		vulns <- vulnerability.Vulnerability{
			Name:                 vulnName,
			AffectedPackageName:  pkgName,
			AffectedPlatformName: "debian 8",
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

	finished <- done.Done{}
	return vulns, finished, errs
}
