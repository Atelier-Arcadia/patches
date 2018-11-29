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
	schedule := newScheduler(100*time.Millisecond, ticks)

	if err := schedule.stop(); err == nil {
		t.Errorf("Should not be able to stop a scheduler that has not been started")
	}
	if err := schedule.start(); err != nil {
		t.Error(err)
	}
	if err := schedule.start(); err == nil {
		t.Errorf("Should not be able to start a scheduler twice")
	}
	<-time.After(350 * time.Millisecond)
	if err := schedule.stop(); err != nil {
		t.Error(err)
	}
	if err := schedule.stop(); err == nil {
		t.Errorf("Should not be able to stop a scheduler twice")
	}

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
