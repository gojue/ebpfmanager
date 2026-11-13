package internal

import "time"

// Retry retries tryFn until success of maximum number of attempts reached.
func Retry(tryFn func() error, attemptCount uint, delay time.Duration) error {
	var err error
	for i := uint(0); i < attemptCount; i++ {
		err = tryFn()
		if err == nil {
			return nil
		}
		time.Sleep(delay)
	}
	return err
}
