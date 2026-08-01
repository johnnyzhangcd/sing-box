//go:build with_globalprotect

package globalprotect

import (
	"errors"
	"testing"
	"time"
)

func TestPermanentRetryMarkerSurvivesWrapping(t *testing.T) {
	marked := markPermanentRetry(errors.New("invalid credentials"))
	if !isPermanentRetry(errors.Join(errors.New("login failed"), marked)) {
		t.Fatal("permanent retry marker was lost through wrapping")
	}
}

func TestRetryBackoffIsExponentialCappedAndJittered(t *testing.T) {
	var backoff retryBackoff
	wantBases := []time.Duration{
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		32 * time.Second,
		60 * time.Second,
		60 * time.Second,
	}
	for _, wantBase := range wantBases {
		delay := backoff.Next()
		spread := wantBase / retryJitterScale
		if backoff.current != wantBase {
			t.Fatalf("unexpected backoff base: got %s, want %s", backoff.current, wantBase)
		}
		if delay < wantBase-spread || delay > wantBase+spread {
			t.Fatalf("jittered delay %s is outside %s..%s", delay, wantBase-spread, wantBase+spread)
		}
	}
	backoff.Reset()
	if backoff.current != 0 {
		t.Fatalf("backoff did not reset: %s", backoff.current)
	}
}
