package limit

import (
	"testing"
	"time"
)

func TestConstantRateLimiter(t *testing.T) {
	pause := 12 * time.Millisecond
	epsilon := float64(4 * time.Millisecond)
	lowerBound := float64(pause) - epsilon
	upperBound := lowerBound + 2*epsilon

	t.Logf("Running TestConstantRateLimiter: Should unblock in a constant interval")

	block := ConstantRateLimiter(pause)
	totalTimePaused := 0 * time.Millisecond

	for i := 0; i < 50; i++ {
		before := time.Now()
		<-block()
		after := time.Now()

		totalTimePaused += after.Sub(before)
	}

	avgTimePaused := float64(totalTimePaused) / 50.0
	withinErrorRange := avgTimePaused <= upperBound && avgTimePaused >= lowerBound

	if !withinErrorRange {
		t.Errorf("Blocked for an average of %f milliseconds when it should have been 12", avgTimePaused)
	}
}
