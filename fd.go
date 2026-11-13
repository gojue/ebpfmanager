package manager

import (
	"errors"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"
)

// errClosedFd - Use of closed file descriptor error
var errClosedFd = errors.New("use of closed file descriptor")

// fd - File descriptor
type fd struct {
	raw int64
}

// newFD - returns a new file descriptor
func newFD(value uint32) *fd {
	f := &fd{int64(value)}
	runtime.SetFinalizer(f, func(f *fd) {
		_ = f.Close()
	})
	return f
}

func (fd *fd) String() string {
	return strconv.FormatInt(fd.raw, 10)
}

func (fd *fd) Value() (uint32, error) {
	if fd.raw < 0 {
		return 0, errClosedFd
	}

	return uint32(fd.raw), nil
}

func (fd *fd) Close() error {
	if fd.raw < 0 {
		return nil
	}

	value := int(fd.raw)
	fd.raw = -1

	runtime.SetFinalizer(fd, nil)
	return unix.Close(value)
}
