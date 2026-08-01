package globalprotect

import (
	"errors"
	"math/rand/v2"
	"time"
)

const (
	initialRetryDelay = 2 * time.Second
	maximumRetryDelay = time.Minute
	retryJitterScale  = 5
)

type permanentRetryError struct {
	cause error
}

func (e *permanentRetryError) Error() string {
	return e.cause.Error()
}

func (e *permanentRetryError) Unwrap() error {
	return e.cause
}

func markPermanentRetry(err error) error {
	if err == nil || isPermanentRetry(err) {
		return err
	}
	return &permanentRetryError{cause: err}
}

func isPermanentRetry(err error) bool {
	var permanentErr *permanentRetryError
	return errors.As(err, &permanentErr)
}

type retryBackoff struct {
	current time.Duration
}

func (b *retryBackoff) Next() time.Duration {
	if b.current == 0 {
		b.current = initialRetryDelay
	} else if b.current < maximumRetryDelay {
		b.current *= 2
		if b.current > maximumRetryDelay {
			b.current = maximumRetryDelay
		}
	}
	spread := b.current / retryJitterScale
	return b.current - spread + time.Duration(rand.Int64N(int64(2*spread)+1))
}

func (b *retryBackoff) Reset() {
	b.current = 0
}
