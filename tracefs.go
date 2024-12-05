package manager

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	traceFSRoot = "/sys/kernel/tracing"
	debugFSRoot = "/sys/kernel/debug/tracing"
)

var (
	tracingRoot = struct {
		once sync.Once
		path string
		err  error
	}{}
)

func getTracefsRoot() (string, error) {
	tracingRoot.once.Do(func() {
		var statfs unix.Statfs_t
		var traceError error
		if traceError = unix.Statfs(traceFSRoot, &statfs); traceError == nil {
			if statfs.Type == unix.TRACEFS_MAGIC {
				tracingRoot.path = traceFSRoot
				return
			}
			traceError = fmt.Errorf("%s is not mounted with tracefs filesystem type", traceFSRoot)
		}
		var debugError error
		if debugError = unix.Statfs(debugFSRoot, &statfs); debugError == nil {
			if statfs.Type == unix.TRACEFS_MAGIC || statfs.Type == unix.DEBUGFS_MAGIC {
				tracingRoot.path = debugFSRoot
				return
			}
			debugError = fmt.Errorf("%s is not mounted with tracefs or debugfs filesystem type", debugFSRoot)
		}

		bestError := fmt.Errorf("tracefs: %s", traceError)
		// only fallback to debugfs error if tracefs doesn't exist at all and debugfs does
		if errors.Is(traceError, syscall.ENOENT) && !errors.Is(debugError, syscall.ENOENT) {
			bestError = fmt.Errorf("debugfs: %s", debugError)
		}
		tracingRoot.err = fmt.Errorf("tracefs or debugfs is not available: %s", bestError)
	})
	return tracingRoot.path, tracingRoot.err
}

// Root returns the tracing root path in use, `/sys/kernel/tracing` (tracefs) or `/sys/kernel/debug/tracing` (debugfs)
func TracefsRoot() (string, error) {
	return getTracefsRoot()
}

// ReadFile reads the relative path provided, using the detected root of tracefs or debugfs
func TracefsReadFile(relname string) ([]byte, error) {
	root, err := getTracefsRoot()
	if err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(root, relname))
}

// Open opens the relative path provided (similar to os.Open), using the detected root of tracefs or debugfs
func TracefsOpen(relname string) (*os.File, error) {
	return TracefsOpenFile(relname, os.O_RDONLY, 0)
}

// OpenFile opens the relative path provided (similar to os.OpenFile), using the detected root of tracefs or debugfs
func TracefsOpenFile(relname string, flag int, perm os.FileMode) (*os.File, error) {
	root, err := getTracefsRoot()
	if err != nil {
		return nil, err
	}
	return os.OpenFile(filepath.Join(root, relname), flag, perm)
}
