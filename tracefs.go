package manager

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gojue/ebpfmanager/internal"
	"github.com/gojue/ebpfmanager/tracefs"
)

const (
	// maxEventNameLen - maximum length for a kprobe (or uprobe) event name
	// MAX_EVENT_NAME_LEN (linux/kernel/trace/trace.h)
	maxEventNameLen    = 64
	minFunctionNameLen = 10
)

type probeType uint8

const (
	kprobe probeType = iota
	uprobe
)

func (p probeType) String() string {
	switch p {
	case kprobe:
		return "kprobe"
	case uprobe:
		return "uprobe"
	default:
		return ""
	}
}

func (p probeType) eventsFilename() string {
	switch p {
	case kprobe:
		return "kprobe_events"
	case uprobe:
		return "uprobe_events"
	default:
		return ""
	}
}

// getUIDSet - Returns the list of UIDs used by this manager.
func (m *Manager) getUIDSet() []string {
	var uidSet []string
	for _, p := range m.Probes {
		if len(p.UID) == 0 {
			continue
		}

		var found bool
		for _, uid := range uidSet {
			if uid == p.UID {
				found = true
				break
			}
		}
		if !found {
			uidSet = append(uidSet, p.UID)
		}
	}
	return uidSet
}

func (m *Manager) getTracefsRegex() (*regexp.Regexp, error) {
	uidSet := m.getUIDSet()
	escapedUIDs := make([]string, len(uidSet))
	for i, uid := range uidSet {
		escapedUIDs[i] = regexp.QuoteMeta(uid)
	}
	stringPattern := fmt.Sprintf(`(p|r)[0-9]*:(kprobes|uprobes)\/(.*(%s)*_([0-9]*)) .*`, strings.Join(escapedUIDs, "|"))
	re, err := regexp.Compile(stringPattern)
	if err != nil {
		return nil, fmt.Errorf("event name pattern (%q) generation failed: %w", stringPattern, err)
	}
	return re, nil
}

// cleanupTraceFS - Cleans up kprobe_events and uprobe_events by removing entries of known UIDs, that are not used
// anymore.
//
// Previous instances of this manager might have been killed unexpectedly. When this happens,
// kprobe_events is not cleaned up properly and can grow indefinitely until it reaches 65k
// entries (see: https://elixir.bootlin.com/linux/v5.6.1/source/kernel/trace/trace_output.c#L699)
// Once the limit is reached, the kernel refuses to load new probes and throws a "no such device"
// error. To prevent this, start by cleaning up the kprobe_events entries of previous managers that
// are not running anymore.
func (m *Manager) cleanupTraceFS() error {
	// Anonymous probes cannot identify stale events owned by this manager.
	if len(m.getUIDSet()) == 0 {
		return nil
	}
	// PMU and bpf_link attachment do not require tracefs. Keep these paths
	// usable on Android and hosts where tracefs is not mounted or accessible.
	// An explicitly requested tracefs attachment still reports its own error.
	if _, err := tracefs.Root(); err != nil {
		return nil
	}
	pattern, err := m.getTracefsRegex()
	if err != nil {
		return fmt.Errorf("tracefs regex: %s", err)
	}

	var cleanUpErrors error
	pidMask := map[int]bool{Getpid(): true}
	eventFiles := []string{kprobe.eventsFilename(), uprobe.eventsFilename()}
	for _, eventFile := range eventFiles {
		events, err := tracefs.ReadFile(eventFile)
		if err != nil {
			cleanUpErrors = errors.Join(cleanUpErrors, fmt.Errorf("read %s: %w", eventFile, err))
			continue
		}

		for _, match := range pattern.FindAllStringSubmatch(string(events), -1) {
			// our probes names should match the pattern provided and have the 5 capture groups + 1 full string
			if len(match) < 6 {
				continue
			}

			// the last capture group is the PID, check if the provided PID still exists
			pid, err := strconv.Atoi(match[5])
			if err != nil {
				continue
			}
			procRunning, ok := pidMask[pid]
			if !ok {
				// this short sleep is used to avoid a CPU spike (5s ~ 60k * 80 microseconds)
				time.Sleep(80 * time.Microsecond)
				procRunning = internal.ProcessExists(pid)
				pidMask[pid] = procRunning
			}
			if procRunning {
				continue
			}
			cleanUpErrors = errors.Join(cleanUpErrors, unregisterTraceFSEvent(eventFile, match[3]))
		}
	}
	return cleanUpErrors
}

func FindFilterFunction(funcName string) (string, error) {
	// Prepare matching pattern
	searchedName, err := regexp.Compile(funcName)
	if err != nil {
		return "", err
	}

	funcsReader, err := tracefs.Open("available_filter_functions")
	if err != nil {
		return "", err
	}
	defer funcsReader.Close()

	funcs := bufio.NewScanner(funcsReader)
	funcs.Split(bufio.ScanLines)

	var potentialMatches []string
	for funcs.Scan() {
		name := funcs.Bytes()
		name, _, _ = bytes.Cut(name, []byte(" "))
		name, _, _ = bytes.Cut(name, []byte("\t"))

		if string(name) == funcName {
			return funcName, nil
		}
		if searchedName.Match(name) {
			potentialMatches = append(potentialMatches, string(name))
		}
	}
	if err := funcs.Err(); err != nil {
		return "", err
	}

	if len(potentialMatches) > 0 {
		return potentialMatches[0], nil
	}
	return "", nil
}

var safeEventRegexp = regexp.MustCompile("[^a-zA-Z0-9]")

func generateEventName(probeType, funcName, UID string, attachPID int) (string, error) {
	// truncate the function name and UID name to reduce the length of the event
	attachPIDstr := strconv.Itoa(attachPID)
	maxFuncNameLen := maxEventNameLen - 3 /* _ */ - len(probeType) - len(UID) - len(attachPIDstr)
	if maxFuncNameLen < minFunctionNameLen { /* let's guarantee that we have a function name minimum of 10 chars (minFunctionNameLen) or trow an error */
		dbgFullEventString := safeEventRegexp.ReplaceAllString(fmt.Sprintf("%s_%s_%s_%s", probeType, funcName, UID, attachPIDstr), "_")
		return "", fmt.Errorf("event name is too long (kernel limit is %d (MAX_EVENT_NAME_LEN)): minFunctionNameLen %d, len 3, probeType %d, funcName %d, UID %d, attachPIDstr %d ; full event string : '%s'", maxEventNameLen, minFunctionNameLen, len(probeType), len(funcName), len(UID), len(attachPIDstr), dbgFullEventString)
	}
	eventName := safeEventRegexp.ReplaceAllString(fmt.Sprintf("%s_%.*s_%s_%s", probeType, maxFuncNameLen, funcName, UID, attachPIDstr), "_")

	if len(eventName) > maxEventNameLen {
		return "", fmt.Errorf("event name too long (kernel limit MAX_EVENT_NAME_LEN is %d): '%s'", maxEventNameLen, eventName)
	}
	return eventName, nil
}

// getKernelGeneratedEventName returns the pattern used by the kernel when a [k|u]probe is loaded without an event name.
// The library doesn't support loading a [k|u]probe with an address directly, so only one pattern applies here.
func getKernelGeneratedEventName(probeType, funcName string) string {
	return fmt.Sprintf("%s_%s_0", probeType, funcName)
}

type traceFsEventArgs struct {
	Type         probeType
	ReturnProbe  bool
	Symbol, Path string
	Offset       uint64
	UID          string
	MaxActive    int
	AttachingPID int
}

func tracefsPrefix(ret bool) string {
	if ret {
		return "r"
	}
	return "p"
}

// TraceFSLock is used to synchronize access to the tracefs events files,
// preventing some issues with concurrent access to it, that can cause some kernel crashes.
var TraceFSLock sync.Mutex

func registerTraceFSEvent(args traceFsEventArgs) (int, string, error) {
	prefix := tracefsPrefix(args.ReturnProbe)
	eventName, err := generateEventName(prefix, args.Symbol, args.UID, args.AttachingPID)
	if err != nil {
		return -1, "", err
	}

	f, err := tracefs.OpenFile(args.Type.eventsFilename(), os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return -1, "", fmt.Errorf("cannot open %s: %w", args.Type.eventsFilename(), err)
	}
	defer f.Close()
	// precompute strings of unknown length
	maxActiveStr := strconv.Itoa(args.MaxActive)
	offsetStr := fmt.Sprintf("%#x", args.Offset)
	token := args.Symbol
	if args.Type == uprobe {
		token = args.Path
	}

	var sb strings.Builder
	// may be larger than necessary, but never smaller
	sb.Grow(len(prefix) + len(maxActiveStr) + 1 + len(eventName) + 1 + len(token) + 1 + len(offsetStr) + 1)
	sb.WriteString(prefix)
	if args.Type == kprobe && args.ReturnProbe && args.MaxActive > 0 {
		sb.WriteString(maxActiveStr)
	}
	sb.WriteRune(':')
	sb.WriteString(eventName)
	sb.WriteRune(' ')
	sb.WriteString(token)
	switch args.Type {
	case kprobe:
		if args.Offset > 0 {
			sb.WriteRune('+')
			sb.WriteString(offsetStr)
		}
	case uprobe:
		sb.WriteRune(':')
		sb.WriteString(offsetStr)
	}
	sb.WriteRune('\n')
	cmd := sb.String()

	// because of https://lore.kernel.org/all/20221121081103.3070449-1-zhengyejian1@huawei.com/T/
	// we take a lock to prevent parallel writes to the trace events file
	TraceFSLock.Lock()

	if _, err = f.WriteString(cmd); err != nil && !os.IsExist(err) {
		TraceFSLock.Unlock()
		return -1, "", fmt.Errorf("cannot write %q to %s: %w", cmd, args.Type.eventsFilename(), err)
	}

	TraceFSLock.Unlock()

	// Retrieve probe ID
	probeIDFile := fmt.Sprintf("events/%ss/%s/id", args.Type.String(), eventName)
	probeIDBytes, err := tracefs.ReadFile(probeIDFile)
	if err != nil {
		if os.IsNotExist(err) {
			return -1, "", ErrProbeIDNotExist
		}
		return -1, "", fmt.Errorf("cannot read probe id: %w", err)
	}
	id := strings.TrimSpace(string(probeIDBytes))
	probeID, err := strconv.Atoi(id)
	if err != nil {
		return -1, "", fmt.Errorf("invalid probe id: '%s': %w", id, err)
	}
	return probeID, eventName, nil
}

func unregisterTraceFSEvent(eventsFile string, name string) error {
	f, err := tracefs.OpenFile(eventsFile, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return fmt.Errorf("open %s: %w", eventsFile, err)
	}
	defer f.Close()
	cmd := fmt.Sprintf("-:%s\n", name)

	// see registerTraceFSEvent for why we take this lock here
	TraceFSLock.Lock()
	defer TraceFSLock.Unlock()

	if _, err = f.WriteString(cmd); err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) && pe.Err == syscall.ENOENT {
			// This can happen when for example two modules
			// use the same elf object and both call `Close()`.
			// The second will encounter the error as the
			// probe already has been cleared by the first.
			return nil
		}
		return fmt.Errorf("write %q to %s: %w", cmd, eventsFile, err)
	}
	return nil
}

// GetTracepointID - Returns a tracepoint ID from its category and name
func GetTracepointID(category, name string) (int, error) {
	tracepointIDFile := fmt.Sprintf("events/%s/%s/id", category, name)
	tracepointIDBytes, err := tracefs.ReadFile(tracepointIDFile)
	if err != nil {
		return -1, fmt.Errorf("cannot read tracepoint id %q: %w", tracepointIDFile, err)
	}
	tracepointID, err := strconv.Atoi(strings.TrimSpace(string(tracepointIDBytes)))
	if err != nil {
		return -1, fmt.Errorf("invalid tracepoint id: %w", err)
	}
	return tracepointID, nil
}

type tracefsLink struct {
	*perfEventLink
	Type      probeType
	EventName string
}

func (l *tracefsLink) Close() error {
	err := l.perfEventLink.Close()
	if l.EventName != "" {
		err = errors.Join(err, unregisterTraceFSEvent(l.Type.eventsFilename(), l.EventName))
	}
	return err
}
