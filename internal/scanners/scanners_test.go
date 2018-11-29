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
