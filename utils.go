package manager

import (
	"bufio"
	"debug/elf"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

type state uint

const (
	reset state = iota
	initialized
	paused
	running

	// maxEventNameLen - maximum length for a kprobe (or uprobe) event name
	// MAX_EVENT_NAME_LEN (linux/kernel/trace/trace.h)
	maxEventNameLen    = 64
	minFunctionNameLen = 10

	// maxBPFClassifierNameLen - maximum length for a TC
	// CLS_BPF_NAME_LEN (linux/net/sched/cls_bpf.c)
	maxBPFClassifierNameLen = 256
)

// ConcatErrors - Concatenate 2 errors into one error.
func ConcatErrors(err1, err2 error) error {
	if err1 == nil {
		return err2
	}
	if err2 != nil {
		return fmt.Errorf("error:%v, error2:%v", err1, err2.Error())
	}
	return err1
}

// availableFilterFunctions - cache of the list of available kernel functions.
var availableFilterFunctions []string

func FindFilterFunction(funcName string) (string, error) {
	// Prepare matching pattern
	searchedName, err := regexp.Compile(funcName)
	if err != nil {
		return "", err
	}

	// Cache available filter functions if necessary
	if len(availableFilterFunctions) == 0 {
		funcs, err := ioutil.ReadFile("/sys/kernel/debug/tracing/available_filter_functions")
		if err != nil {
			return "", err
		}
		availableFilterFunctions = strings.Split(string(funcs), "\n")
		for i, name := range availableFilterFunctions {
			splittedName := strings.Split(name, " ")
			name = splittedName[0]
			splittedName = strings.Split(name, "\t")
			name = splittedName[0]
			availableFilterFunctions[i] = name
		}
		sort.Strings(availableFilterFunctions)
	}

	// Match function name
	var potentialMatches []string
	for _, f := range availableFilterFunctions {
		if searchedName.MatchString(f) {
			potentialMatches = append(potentialMatches, f)
		}
		if f == funcName {
			return f, nil
		}
	}
	if len(potentialMatches) > 0 {
		return potentialMatches[0], nil
	}
	return "", nil
}

// cache of the syscall prefix depending on kernel version
var syscallPrefix string

// GetSyscallFnName - Returns the kernel function of the provided syscall, after reading /proc/kallsyms to retrieve
// the list of symbols of the current kernel.
func GetSyscallFnName(name string) (string, error) {
	return GetSyscallFnNameWithSymFile(name, defaultSymFile)
}

// cache of the symfile
var kallsymsCache = make(map[string]bool)

// GetSyscallFnNameWithSymFile - Returns the kernel function of the provided syscall, after reading symFile to retrieve
// the list of symbols of the current kernel.
func GetSyscallFnNameWithSymFile(name string, symFile string) (string, error) {
	if symFile == "" {
		symFile = defaultSymFile
	}

	// Get name from kallsyms cache
	if len(kallsymsCache) == 0 {
		file, err := os.Open(symFile)
		if err != nil {
			return "", err
		}
		defer file.Close()
		// cache up the kallsyms for speed up
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.Split(scanner.Text(), " ")
			if len(line) < 3 {
				continue
			}
			// only save symbol in text (code) section and weak symbol
			// Reference: https://github.com/iovisor/bcc/pull/1540/files
			if strings.ToLower(line[1]) == "t" || strings.ToLower(line[1]) == "w" {
				kallsymsCache[line[2]] = true
			}
		}
	}

	if _, exist := kallsymsCache[name]; exist {
		return name, nil
	}

	if syscallPrefix == "" {
		syscallName, err := getSyscallName("open", symFile)
		if err != nil {
			return "", err
		}

		syscallPrefix = strings.TrimSuffix(syscallName, "open")
	}

	return syscallPrefix + name, nil
}

const defaultSymFile = "/proc/kallsyms"

// Returns the qualified syscall named by going through '/proc/kallsyms' on the
// system on which its executed. It allows BPF programs that may have been compiled
// for older syscall functions to run on newer kernels
func getSyscallName(name string, symFile string) (string, error) {
	// Get kernel symbols
	syms, err := ioutil.ReadFile(symFile)
	if err != nil {
		return "", err
	}
	return getSyscallFnNameWithKallsyms(name, string(syms))
}

func getSyscallFnNameWithKallsyms(name string, kallsymsContent string) (string, error) {
	var arch string
	switch runtime.GOARCH {
	case "386":
		arch = "ia32"
	case "arm64":
		arch = "arm64"
	default:
		arch = "x64"
	}
	var b strings.Builder

	// We should search for new syscall function like "__x64__sys_open"
	// Note the start of word boundary. Should return exactly one string
	regexStr := `(\b__` + arch + `_[Ss]y[sS]_` + name + `\b)`
	fnRegex := regexp.MustCompile(regexStr)

	match := fnRegex.FindString(kallsymsContent)
	if len(match) > 0 {
		b.WriteString(match)
		return b.String(), nil
	}

	// If nothing found, search for old syscall function to be sure
	regexStr = `(\b[Ss]y[sS]_` + name + `\b)`
	fnRegex = regexp.MustCompile(regexStr)
	match = fnRegex.FindString(kallsymsContent)
	// If we get something like 'sys_open' or 'SyS_open', return
	// either (they have same addr) else, just return original string
	if len(match) > 0 {
		b.WriteString(match)
		return b.String(), nil
	}

	// check for '__' prefixed functions, like '__sys_open'
	regexStr = `(\b__[Ss]y[sS]_` + name + `\b)`
	fnRegex = regexp.MustCompile(regexStr)
	match = fnRegex.FindString(kallsymsContent)
	// If we get something like '__sys_open' or '__SyS_open', return
	// either (they have same addr) else, just return original string
	if len(match) > 0 {
		b.WriteString(match)
		return b.String(), nil
	}

	return "", errors.New("could not find a valid syscall name")
}

var safeEventRegexp = regexp.MustCompile("[^a-zA-Z0-9]")

func GenerateEventName(probeType, funcName, UID string, attachPID int) (string, error) {
	// truncate the function name and UID name to reduce the length of the event
	attachPIDstr := strconv.Itoa(attachPID)
	maxFuncNameLen := (maxEventNameLen - 3 /* _ */ - len(probeType) - len(UID) - len(attachPIDstr))
	if maxFuncNameLen < minFunctionNameLen { /* let's garantee that we have a function name minimum of 10 chars (minFunctionNameLen) of trow an error */
		dbgFullEventString := safeEventRegexp.ReplaceAllString(fmt.Sprintf("%s_%s_%s_%s", probeType, funcName, UID, attachPIDstr), "_")
		return "", fmt.Errorf("event name is too long (kernel limit is %d (MAX_EVENT_NAME_LEN)): minFunctionNameLen %d, len 3, probeType %d, funcName %d, UID %d, attachPIDstr %d ; full event string : '%s'", maxEventNameLen, minFunctionNameLen, len(probeType), len(funcName), len(UID), len(attachPIDstr), dbgFullEventString)
	}
	eventName := safeEventRegexp.ReplaceAllString(fmt.Sprintf("%s_%.*s_%s_%s", probeType, maxFuncNameLen, funcName, UID, attachPIDstr), "_")

	if len(eventName) > maxEventNameLen {
		return "", fmt.Errorf("event name too long (kernel limit MAX_EVENT_NAME_LEN is %d): '%s'", maxEventNameLen, eventName)
	}
	return eventName, nil
}

// OpenAndListSymbols - Opens an elf file and extracts all its symbols
func OpenAndListSymbols(path string) (*elf.File, []elf.Symbol, error) {
	// open elf file
	f, err := elf.Open(path)
	if err != nil {
		return nil, nil, errors.New(fmt.Sprintf("error:%v , couldn't open elf file %s", err, path))
	}
	defer f.Close()

	// Loop through all symbols
	syms, errSyms := f.Symbols()
	dynSyms, errDynSyms := f.DynamicSymbols()
	syms = append(syms, dynSyms...)

	if len(syms) == 0 {
		var err error
		if errSyms != nil {
			err = errors.New(fmt.Sprintf("error:%v , failed to list symbols", err))
		}
		if errDynSyms != nil {
			err = errors.New(fmt.Sprintf("error:%v , failed to list dynamic symbols", err))
		}
		if err != nil {
			return nil, nil, err
		} else {
			return nil, nil, errors.New("no symbols found")
		}
	}
	return f, syms, nil
}

// SanitizeUprobeAddresses - sanitizes the addresses of the provided symbols
func SanitizeUprobeAddresses(f *elf.File, syms []elf.Symbol) {
	// If the binary is a non-PIE executable, addr must be a virtual address, otherwise it must be an offset relative to
	// the file load address. For executable (ET_EXEC) binaries and shared objects (ET_DYN), translate the virtual
	// address to physical address in the binary file.
	if f.Type == elf.ET_EXEC || f.Type == elf.ET_DYN {
		for i, sym := range syms {
			for _, prog := range f.Progs {
				if prog.Type == elf.PT_LOAD {
					if sym.Value >= prog.Vaddr && sym.Value < (prog.Vaddr+prog.Memsz) {
						syms[i].Value = sym.Value - prog.Vaddr + prog.Off
					}
				}
			}
		}
	}
}

// FindSymbolOffsets - Parses the provided file and returns the offsets of the symbols that match the provided pattern
func FindSymbolOffsets(path string, pattern *regexp.Regexp) ([]elf.Symbol, error) {
	f, syms, err := OpenAndListSymbols(path)
	if err != nil {
		return nil, err
	}

	var matches []elf.Symbol
	for _, sym := range syms {
		if elf.ST_TYPE(sym.Info) == elf.STT_FUNC && pattern.MatchString(sym.Name) {
			matches = append(matches, sym)
		}
	}

	if len(matches) == 0 {
		return nil, ErrSymbolNotFound
	}

	SanitizeUprobeAddresses(f, matches)
	return matches, nil
}

func generateTCFilterName(UID, sectionName string, attachPID int) (string, error) {
	attachPIDstr := strconv.Itoa(attachPID)
	maxSectionNameLen := maxBPFClassifierNameLen - 3 /* _ */ - len(UID) - len(attachPIDstr)
	if maxSectionNameLen < 0 {
		dbgFullFilterString := safeEventRegexp.ReplaceAllString(fmt.Sprintf("%s_%s_%s", sectionName, UID, attachPIDstr), "_")
		return "", fmt.Errorf("filter name is too long (kernel limit is %d (CLS_BPF_NAME_LEN)): sectionName %d, UID %d, attachPIDstr %d ; full event string : '%s'", maxEventNameLen, len(sectionName), len(UID), len(attachPIDstr), dbgFullFilterString)
	}
	filterName := safeEventRegexp.ReplaceAllString(fmt.Sprintf("%.*s_%s_%s", maxSectionNameLen, sectionName, UID, attachPIDstr), "_")

	if len(filterName) > maxBPFClassifierNameLen {
		return "", fmt.Errorf("filter name too long (kernel limit CLS_BPF_NAME_LEN is %d): '%s'", maxBPFClassifierNameLen, filterName)
	}
	return filterName, nil
}
