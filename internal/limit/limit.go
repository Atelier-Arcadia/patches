package limit

import (
	"time"

	"github.com/Atelier-Arcadia/patches/pkg/done"
)

// RateLimiter is a function that, similar to time.After, returns a channel from
// which one value will be read.  This channel should only be written to after
// some amount of time has passed, allowing callers to reduce the speed with which
// they perform work.
type RateLimiter func() <-chan done.Done

// ConstantRateLimiter produces a RateLimiter that always unblocks after a
// particular duration of time.
func ConstantRateLimiter(pause time.Duration) RateLimiter {
	return func() <-chan done.Done {
		fin := make(chan done.Done, 1)

		go func() {
			<-time.After(pause)
			fin <- done.Done{}
		}()

		return fin
	}
}
