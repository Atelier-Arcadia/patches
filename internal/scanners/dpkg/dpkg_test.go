package dpkg

import (
	"os/exec"
	"testing"

	"github.com/zsck/patches/pkg/pack"
)

func TestScannerImplementation(t *testing.T) {
	dpkgIsInstalled := isDpkgInstalled()

	testCases := []struct {
		Description  string
		Package      pack.Package
		ExpectToFind pack.Found
		ExpectError  bool
	}{
		{
			Description: "Should find a package that's almost guaranteed to be present",
			Package: pack.Package{
				Name:    "bash",
				Version: ".*",
			},
			ExpectToFind: pack.WasFound,
			ExpectError:  dpkgIsInstalled,
		},
		{
			Description: "Should not find a package doesn't exist",
			Package: pack.Package{
				Name:    "madeupnamenotrealpackage",
				Version: ".*",
			},
			ExpectToFind: pack.NotFound,
			ExpectError:  dpkgIsInstalled,
		},
	}

	for caseNum, testCase := range testCases {
		t.Logf("Running TestScannerImplementation case #%d: %s\n", caseNum, testCase.Description)

		scanner := NewScanner()

		wasFound, err := scanner.Scan(testCase.Package)

		gotErr := err != nil
		if gotErr && !testCase.ExpectError {
			t.Fatalf("Did not expect to get an error, but got '%s'", err.Error())
		} else if !gotErr && testCase.ExpectError {
			t.Fatalf("Expected to get an error but did not")
		}

		if wasFound != testCase.ExpectToFind {
			t.Errorf("Expected to find package? %v Found? %v", testCase.ExpectToFind, wasFound)
		}
	}
}

func isDpkgInstalled() bool {
	output, err := exec.Command("banana").Output()

	if err != nil {
		return false
	}

	return len(output) > 0
}
