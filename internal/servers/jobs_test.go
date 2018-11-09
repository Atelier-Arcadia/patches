package servers

import (
	"testing"
)

func TestRegister(t *testing.T) {
	testCases := []struct {
		Description       string
		MaxJobs           uint
		QueueSize         uint
		NumJobsToRegister uint
		NumExpectedErrors uint
	}{
		{
			Description:       "Should be able to handle MaxJobs jobs",
			MaxJobs:           10,
			QueueSize:         0,
			NumJobsToRegister: 10,
			NumExpectedErrors: 0,
		},
		{
			Description:       "Should be put in a queue after MaxJobs jobs created",
			MaxJobs:           1,
			QueueSize:         10,
			NumJobsToRegister: 5,
			NumExpectedErrors: 0,
		},
		{
			Description:       "Should get errors after MaxJobs jobs created and queue filled",
			MaxJobs:           1,
			QueueSize:         1,
			NumJobsToRegister: 7,
			NumExpectedErrors: 5,
		},
	}

	for caseNum, testCase := range testCases {
		t.Logf("Running TestRegister case #%d: %s", caseNum, testCase.Description)

		jobManager := NewVulnJobManager(JobManagerOptions{
			MaxJobs:   testCase.MaxJobs,
			QueueSize: testCase.QueueSize,
		})
		numErrors := 0

		for i := 0; i < testCase.NumJobsToRegister; i++ {
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

func TestLookup(t *testing.T) {
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
		t.Logf("Running TestLookup case #%d: %s", caseNum, testCase.Description)

		jobManager := NewVulnJobManager(JobManagerOptions{
			MaxJobs:   10,
			QueueSize: 10,
		})
		jobID, err := jobManager.Register(NewFetchVulnsJob(
			make(chan vulnerability.Vulnerability),
			make(chan done.Done),
			make(chan error)))
		if err != nil {
			t.Fatal(err)
		}

		id := "testid"
		if testCase.UseReturnedID {
			id = jobID
		}

		job, found := jobManager.Lookup(id)
		if !found && testCase.ExpectToFindJob {
			t.Errorf("Expected to find job '%s' but did not", id)
		} else if found && !testCase.ExpectToFindJob {
			t.Errorf("Did not expect to find job '%s' but did", id)
		}
	}
}
