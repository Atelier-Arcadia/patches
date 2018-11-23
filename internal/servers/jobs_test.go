package servers

import (
	"testing"

	"github.com/arcrose/patches/pkg/done"
	"github.com/arcrose/patches/pkg/vulnerability"
)

func TestRegister(t *testing.T) {
	testCases := []struct {
		Description       string
		MaxJobs           uint
		NumJobsToRegister uint
		NumExpectedErrors uint
	}{
		{
			Description:       "Should be able to handle MaxJobs jobs",
			MaxJobs:           10,
			NumJobsToRegister: 10,
			NumExpectedErrors: 0,
		},
		{
			Description:       "Should get errors after MaxJobs jobs created",
			MaxJobs:           1,
			NumJobsToRegister: 6,
			NumExpectedErrors: 5,
		},
	}

	for caseNum, testCase := range testCases {
		t.Logf("Running TestRegister case #%d: %s", caseNum, testCase.Description)

		jobManager := NewVulnJobManager(VulnJobManagerOptions{
			MaxJobs: testCase.MaxJobs,
		})
		var numErrors uint = 0

		var i uint
		for i = 0; i < testCase.NumJobsToRegister; i++ {
			_, err := jobManager.Register(NewFetchVulnsJob(
				make(chan vulnerability.Vulnerability),
				make(chan done.Done),
				make(chan error)))
			if err != nil {
				numErrors++
			}
		}

		if numErrors != testCase.NumExpectedErrors {
			t.Errorf("Expected to get %d errors, but got %d", testCase.NumExpectedErrors, numErrors)
		}
	}
}

func TestRetrieve(t *testing.T) {
	testCases := []struct {
		Description     string
		UseReturnedID   bool
		ExpectToFindJob bool
	}{
		{
			Description:     "Should be able to find a managed job",
			UseReturnedID:   true,
			ExpectToFindJob: true,
		},
		{
			Description:     "Should not find a job that isn't being managed",
			UseReturnedID:   false,
			ExpectToFindJob: false,
		},
	}

	for caseNum, testCase := range testCases {
		t.Logf("Running TestRetrieve case #%d: %s", caseNum, testCase.Description)

		jobManager := NewVulnJobManager(VulnJobManagerOptions{
			MaxJobs: 10,
		})

		finished := make(chan done.Done)
		//finished <- done.Done{}

		jobID, err := jobManager.Register(NewFetchVulnsJob(
			make(chan vulnerability.Vulnerability),
			finished,
			make(chan error)))
		if err != nil {
			t.Fatal(err)
		}

		id := "testid"
		if testCase.UseReturnedID {
			id = jobID
		}

		_, errs := jobManager.Retrieve(id)
		found := len(errs) == 0
		if !found && testCase.ExpectToFindJob {
			t.Errorf("Expected to find job '%s' but did not", id)
		} else if found && !testCase.ExpectToFindJob {
			t.Errorf("Did not expect to find job '%s' but did", id)
		}
	}
}
