package manager

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var (
	// kprobePMUType is used to cache the kprobe PMY type value
	kprobePMUType = struct {
		once  sync.Once
		value uint32
		err   error
	}{}
	// uprobePMUType is used to cache the uprobe PMU type value
	uprobePMUType = struct {
		once  sync.Once
		value uint32
		err   error
	}{}
)

func parsePMUEventType(eventType probeType) (uint32, error) {
	PMUTypeFile := fmt.Sprintf("/sys/bus/event_source/devices/%s/type", eventType)
	f, err := os.Open(PMUTypeFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, fmt.Errorf("pmu type %s: %w", eventType, ErrNotSupported)
		}
		return 0, fmt.Errorf("couldn't open %s: %w", PMUTypeFile, err)
	}

	var t uint32
	_, err = fmt.Fscanf(f, "%d\n", &t)
	if err != nil {
		return 0, fmt.Errorf("couldn't parse type at %s: %v", eventType, err)
	}
	return t, nil
}

// getPMUEventType reads a Performance Monitoring Unit's type (numeric identifier)
// from /sys/bus/event_source/devices/<pmu>/type.
func getPMUEventType(eventType probeType) (uint32, error) {
	switch eventType {
	case kprobe:
		kprobePMUType.once.Do(func() {
			kprobePMUType.value, kprobePMUType.err = parsePMUEventType(eventType)
		})
		return kprobePMUType.value, kprobePMUType.err
	case uprobe:
		uprobePMUType.once.Do(func() {
			uprobePMUType.value, uprobePMUType.err = parsePMUEventType(eventType)
		})
		return uprobePMUType.value, uprobePMUType.err
	default:
		return 0, fmt.Errorf("unknown event type: %s", eventType)
	}
}

var (
	// kprobeRetProbeBit is used to cache the KProbe RetProbe bit value
	kprobeRetProbeBit = struct {
		once  sync.Once
		value uint64
		err   error
	}{}
	// uprobeRetProbeBit is used to cache the UProbe RetProbe bit value
	uprobeRetProbeBit = struct {
		once  sync.Once
		value uint64
		err   error
	}{}
)

// parseRetProbeBit reads a Performance Monitoring Unit's retprobe bit
// from /sys/bus/event_source/devices/<pmu>/format/retprobe.
func parseRetProbeBit(eventType probeType) (uint64, error) {
	p := filepath.Join("/sys/bus/event_source/devices/", eventType.String(), "/format/retprobe")

	data, err := os.ReadFile(p)
	if err != nil {
		return 0, err
	}

	var rp uint64
	n, err := fmt.Sscanf(string(bytes.TrimSpace(data)), "config:%d", &rp)
	if err != nil {
		return 0, fmt.Errorf("parse retprobe bit: %w", err)
	}
	if n != 1 {
		return 0, fmt.Errorf("parse retprobe bit: expected 1 item, got %d", n)
	}

	return rp, nil
}

func getRetProbeBit(eventType probeType) (uint64, error) {
	switch eventType {
	case kprobe:
		kprobeRetProbeBit.once.Do(func() {
			kprobeRetProbeBit.value, kprobeRetProbeBit.err = parseRetProbeBit(eventType)
		})
		return kprobeRetProbeBit.value, kprobeRetProbeBit.err
	case uprobe:
		uprobeRetProbeBit.once.Do(func() {
			uprobeRetProbeBit.value, uprobeRetProbeBit.err = parseRetProbeBit(eventType)
		})
		return uprobeRetProbeBit.value, uprobeRetProbeBit.err
	default:
		return 0, fmt.Errorf("unknown event type %s", eventType)
	}
}
