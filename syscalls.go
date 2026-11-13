package manager

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

// Cache resolutions by symbol file and input, keeping independent kernel views separate.
var syscallNames sync.Map

func GetSyscallFnName(name string) (string, error) {
	return GetSyscallFnNameWithSymFile(name, defaultSymFile)
}

// GetSyscallFnNameWithSymFile preserves exact kernel symbols before applying
// architecture-specific syscall prefixes. Both "open" and "sys_open" are accepted.
func GetSyscallFnNameWithSymFile(name, symFile string) (string, error) {
	if symFile == "" {
		symFile = defaultSymFile
	}
	key := [2]string{symFile, name}
	if cached, ok := syscallNames.Load(key); ok {
		return cached.(string), nil
	}
	file, err := os.Open(symFile)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[2] == name && strings.Contains("tTwW", fields[1]) {
			syscallNames.Store(key, name)
			return name, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	resolved, err := getSyscallName(strings.TrimPrefix(name, "sys_"), symFile)
	if err != nil {
		return "", err
	}
	syscallNames.Store(key, resolved)
	return resolved, nil
}

const defaultSymFile = "/proc/kallsyms"

// Returns the qualified syscall named by going through '/proc/kallsyms' on the
// system on which its executed. It allows bpf programs that may have been compiled
// for older syscall functions to run on newer kernels
func getSyscallName(name string, symFile string) (string, error) {
	// Get kernel symbols
	syms, err := os.Open(symFile)
	if err != nil {
		return "", err
	}
	defer syms.Close()

	return getSyscallFnNameWithKallsyms(name, syms, "")
}

func getSyscallFnNameWithKallsyms(name string, kallsymsContent io.Reader, arch string) (string, error) {
	if arch == "" {
		switch runtime.GOARCH {
		case "386":
			arch = "ia32"
		case "arm64":
			arch = "arm64"
		case "loong64":
			arch = "loongarch"
		default:
			arch = "x64"
		}
	}

	// We should search for new syscall function like "__x64__sys_open"
	// Note the start of word boundary. Should return exactly one string
	newSyscall := regexp.MustCompile(`\b__` + arch + `_[Ss]y[sS]_` + regexp.QuoteMeta(name) + `\b`)
	// If nothing found, search for old syscall function to be sure
	oldSyscall := regexp.MustCompile(`\b[Ss]y[sS]_` + regexp.QuoteMeta(name) + `\b`)
	// check for '__' prefixed functions, like '__sys_open'
	prefixed := regexp.MustCompile(`\b__[Ss]y[sS]_` + regexp.QuoteMeta(name) + `\b`)

	// the order of patterns is important
	// we first want to look for the new syscall format, then the old format, then the prefixed format
	patterns := []struct {
		pattern *regexp.Regexp
		result  string
	}{
		{newSyscall, ""},
		{oldSyscall, ""},
		{prefixed, ""},
	}

	scanner := bufio.NewScanner(kallsymsContent)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		line := scanner.Text()

		if !strings.Contains(line, name) {
			continue
		}

		for i := range patterns {
			p := &patterns[i]
			// if we already found a match for this pattern we continue
			if p.result != "" {
				continue
			}

			if res := p.pattern.FindString(line); res != "" {
				// fast path for first match on first pattern
				if i == 0 {
					return res, nil
				}

				p.result = res
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	for _, p := range patterns {
		if p.result != "" {
			return p.result, nil
		}
	}

	return "", fmt.Errorf("could not find a valid syscall name")
}
