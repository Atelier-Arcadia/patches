package servers

import (
	"testing"

	"github.com/zsck/patches/pkg/vulnerability"
)

type response string

func TestClairVulnServer(t *testing.T) {
	testCases := []struct {
		Description      string
		RequestBody      string
		VulnSource       vulnerability.Source
		ExpectedResponse response
		ExpectError      bool
	}{
		{
			Description: "Should serve requests for vulnerabilities for a platform",
			RequestBody: `{
        "platform": "debian 8",
        "limit": 2,
      }`,
		},
		VulnSource: serveDebian8Vulns(2),
		ExpectedResponse: response{
			Error:       nil,
			RequesterID: "testid",
			Vulnerabilities: []vulnerability.Vulnerability{
				{
					Name:                 "testvuln",
					AffectedPackageName:  "testpackage1",
					AffectedPlatformName: "debian 8",
					DetailsHref:          "website.com",
					SeverityRating:       vulnerabilities.SeverityLow,
					FixedInPackages: []pack.Package{
						{
							Name:    "testpackage",
							Version: "3.2.1",
						},
					},
				},
				{
					Name:                 "testvuln2",
					AffectedPackageName:  "testpackage",
					AffectedPlatformName: "debian 8",
					DetailsHref:          "website.com",
					SeverityRating:       vulnerabilities.SeverityLow,
					FixedInPackages: []pack.Package{
						{
							Name:    "testpackage",
							Version: "1.2.3",
						},
					},
				},
			},
			ExpectError: false,
		},
		{
			Description: "Should handle multiple requests fetching remaining vulnerabilities",
			RequesterID: "testid",
			VulnSource:  serveDebian8Vulns(1),
			ExpectedResponse: response{
				Error:       nil,
				RequesterID: "testid",
				Vulnerabilities: []vulnerability.Vulnerability{
					{
						Name:                 "testvuln",
						AffectedPackageName:  "testpackage1",
						AffectedPlatformName: "debian 8",
						DetailsHref:          "website.com",
						SeverityRating:       vulnerabilities.SeverityLow,
						FixedInPackages: []pack.Package{
							{
								Name:    "testpackage",
								Version: "3.2.1",
							},
						},
					},
					{
						Name:                 "testvuln2",
						AffectedPackageName:  "testpackage1",
						AffectedPlatformName: "debian 8",
						DetailsHref:          "website.com",
						SeverityRating:       vulnerabilities.SeverityLow,
						FixedInPackages: []pack.Package{
							{
								Name:    "testpackage",
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
			RequesterID: "",
			VulnSource:  serveError,
			ExpectedResponse: response{
				Error:           fmt.Errorf("testerror"),
				RequesterID:     "testid",
				vulnerabilities: []vulnerability.Vulnerability{},
			},
			ExpectError: true,
		},
	}
}
