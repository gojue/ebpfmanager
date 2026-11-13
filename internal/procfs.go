package internal

import (
	"os"
	"strconv"
)

// ProcessExists returns true if the process exists, using the HOST_PROC environment variable if present.
func ProcessExists(pid int) bool {
	file, err := os.Open(hostProc(strconv.Itoa(pid)))
	if err != nil {
		return false
	}
	defer file.Close()
	return true
}
