package manager

import "errors"

var (
	ErrRingbufNotSupported = errors.New("ringbuf is not supported on this kernel, need kernel version >= 5.8.0")
	ErrLSMNotSupported     = errors.New("LSM is not supported on this kernel, need kernel version >= 5.7.0")
)
