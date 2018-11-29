package scanners

import (
	"testing"
	"time"
)

func TestCancel(t *testing.T) {
	cancel := NewCancel()
	go func() {
		for !cancel.Check() {
			<-time.After(50 * time.Millisecond)
		}
		if err := cancel.Confirm(); err != nil {
			t.Error(err)
		}
	}()
	cancel.Terminate()

	if err := cancel.Confirm(); err == nil {
		t.Errorf("Expected a second call to Cancel.Confirm to return an error")
	}
}

func TestScheduler(t *testing.T) {
	ticks := make(chan bool, 5)
	schedule := newScheduler(100*time.Millisecond, ticks, nil)
	schedule.start()
	<-time.After(300 * time.Millisecond)
	schedule.stop()

	ticksReceived := 0
	for ticksReceived < 3 {
		<-ticks
		ticksReceived++
	}

	select {
	case <-ticks:
		t.Errorf("Schedule should not send any more ticks after being stopped")

	default:
		break
	}
}
