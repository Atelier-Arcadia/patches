package clients

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arcrose/patches/pkg/pack"
	"github.com/arcrose/patches/pkg/vulnerability"
)

type response struct {
	Error           *string                       `json:"error"`
	RequestID       string                        `json:"requestID"`
	Vulnerabilities []vulnerability.Vulnerability `json:"vulns"`
}

func TestClient(t *testing.T) {
	errorMsg := "testerror"

	testCases := []struct {
		Description      string
		PlatformName     string
		RequestHandler   http.HandlerFunc
		ExpectedResponse response
	}{
		{
			Description:    "Should retrieve all vulnerabilities returned by the server",
			PlatformName:   "debian-8",
			RequestHandler: serveVulns(2),
			ExpectedResponse: response{
				Error:     nil,
				RequestID: "testid",
				Vulnerabilities: []vulnerability.Vulnerability{
					{
						Name:                 "testvuln",
						AffectedPackageName:  "testpackage",
						AffectedPlatformName: "debian-8",
						DetailsHref:          "link",
						SeverityRating:       vulnerability.SeverityLow,
						FixedInPackages: []pack.Package{
							{
								Name:    "testpackage",
								Version: "1.2.3",
							},
						},
					},
					{
						Name:                 "testvuln",
						AffectedPackageName:  "testpackage",
						AffectedPlatformName: "debian-8",
						DetailsHref:          "link",
						SeverityRating:       vulnerability.SeverityLow,
						FixedInPackages: []pack.Package{
							{
								Name:    "testpackage",
								Version: "1.2.3",
							},
						},
					},
				},
			},
		},
		{
			Description:    "Should return an error if the server returns one",
			PlatformName:   "debian-8",
			RequestHandler: serveError,
			ExpectedResponse: response{
				Error:           &errorMsg,
				RequestID:       "",
				Vulnerabilities: []vulnerability.Vulnerability{},
			},
		},
	}

	for caseNum, testCase := range testCases {
		t.Logf("Running TestClient case %d: %s", caseNum, testCase.Description)

		func() {
			server := httptest.NewServer(testCase.RequestHandler)
			defer server.Close()

			url := fmt.Sprintf("%s/vulns?platform=%s", server.URL, testCase.PlatformName)
			resp, err := http.Get(url)
			if err != nil {
				t.Fatal(err)
			}

			respData := response{}
			decoder := json.NewDecoder(resp.Body)
			decodeErr := decoder.Decode(&respData)
			defer resp.Body.Close()
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}

			if respData.Error != nil &&
				testCase.ExpectedResponse.Error != nil &&
				*respData.Error != *testCase.ExpectedResponse.Error {
				t.Errorf(
					"Expected to get error '%s' but got '%s'",
					*testCase.ExpectedResponse.Error,
					*respData.Error)
			}

			if respData.RequestID != testCase.ExpectedResponse.RequestID {
				t.Errorf(
					"Expected to get request id '%s' but got '%s'",
					testCase.ExpectedResponse.RequestID,
					respData.RequestID)
			}

			for _, expected := range testCase.ExpectedResponse.Vulnerabilities {
				wasFound := false
				for _, found := range respData.Vulnerabilities {
					if found.Equals(expected) {
						wasFound = true
						break
					}
				}
				if !wasFound {
					t.Errorf("Did not find vulnerability: %s", expected.String())
				}
			}
		}()
	}
}

func serveVulns(num uint) http.HandlerFunc {
	var served uint = 0

	return func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")

		if served >= num {
			res.WriteHeader(http.StatusInternalServerError)
			res.Write([]byte(`{
        "error": "no more vulnerabilies to serve",
        "requestID": "",
        "vulnerabilities": []
      }`))
			return
		}

		qs := req.URL.Query()
		platforms, found1 := qs["platform"]
		requestIDs, found2 := qs["requestID"]
		errMsg := ""
		if !found1 || len(platforms) == 0 {
			errMsg = "missing field platform"
		}
		if served > 0 && (!found2 || len(requestIDs) == 0) {
			errMsg = "missing field requestID"
		}

		if errMsg != "" {
			res.WriteHeader(http.StatusBadRequest)
			res.Write([]byte(fmt.Sprintf(`{
        "error": "%s",
        "requestID": "",
        "vulnerabilities": []
      }`, errMsg)))
			return
		}

		res.Write([]byte(`{
      "error": null,
      "requestID": "testid",
      "vulnerabilities": [
        {
          "name": "testvuln",
          "affectedPackageName": "testpackage",
          "affectedPlatform": "debian-8",
          "detailsHref": "link",
          "severityRating": "low",
          "fixedInPackages": [
            {
              "name": "testpackage",
              "version": "1.2.3"
            }
          ]
        }
      ]
    }`))
	}
}

func serveError(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusBadRequest)
	res.Header().Set("Content-Type", "application/json")
	res.Write([]byte(`{
    "error": "testerror",
    "requestID": "",
    "vulnerabilities": []
  }`))
}
