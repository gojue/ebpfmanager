package manager

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/cilium/ebpf"
)

// getEnv retrieves the environment variable key. If it does not exist it returns the default.
func getEnv(key string, dfault string, combineWith ...string) string {
	value := os.Getenv(key)
	if value == "" {
		value = dfault
	}

	switch len(combineWith) {
	case 0:
		return value
	case 1:
		return filepath.Join(value, combineWith[0])
	default:
		all := make([]string, len(combineWith)+1)
		all[0] = value
		copy(all[1:], combineWith)
		return filepath.Join(all...)
	}
}

// hostProc returns joins the provided path with the host /proc directory
func hostProc(combineWith ...string) string {
	return getEnv("HOST_PROC", "/proc", combineWith...)
}

// Getpid returns the current process ID in the host namespace if $HOST_PROC is defined, the pid in the current namespace
// otherwise
func Getpid() int {
	p, err := os.Readlink(hostProc("/self"))
	if err == nil {
		if pid, err := strconv.ParseInt(p, 10, 32); err == nil {
			return int(pid)
		}
	}
	return os.Getpid()
}

// cleanupProgramSpec removes unused internal fields to free up some memory
func cleanupProgramSpec(spec *ebpf.ProgramSpec) {
	if spec != nil {
		spec.Instructions = nil
	}
}

// create slice of length n and fill with fillVal
func makeAndSet[E any](n int, fillVal E) []E {
	s := make([]E, n)
	for i := range s {
		s[i] = fillVal
	}
	return s
}
