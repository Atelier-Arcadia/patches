package limit

import (
	"testing"
	"time"
)

func TestConstantRateLimiter(t *testing.T) {
	pause := 12 * time.Millisecond
	epsilon := 500 * time.Microsecond

	t.Logf("Running TestConstantRateLimiter: Should unblock in a constant interval")

	block := ConstantRateLimiter(pause)
	totalTimePaused := 0 * time.Millisecond

	for i := 0; i < 50; i++ {
		before := time.Now()
		<-block()
		after := time.Now()

		totalTimePaused += after.Sub(before)
	}

	avgTimePaused := totalTimePaused / 50
	withinErrorRange := avgTimePaused < (pause+epsilon) &&
		avgTimePaused > (pause-epsilon)

	if !withinErrorRange {
		t.Errorf("Did not block for an average of 12 milliseconds across 50 blocks")
	}
}
