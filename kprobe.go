package manager

import (
	"errors"
	"fmt"
	"os"
)

type KprobeAttachMethod = AttachMethod

const (
	AttachKprobeMethodNotSet      = AttachMethodNotSet
	AttachKprobeWithPerfEventOpen = AttachWithPerfEventOpen
	AttachKprobeWithKprobeEvents  = AttachWithProbeEvents
)

func (p *Probe) prefix() string {
	return tracefsPrefix(p.isReturnProbe)
}

type attachFunc func() (*tracefsLink, error)

// attachKprobe - Attaches the probe to its kprobe
func (p *Probe) attachKprobe() error {
	if len(p.HookFuncName) == 0 {
		return fmt.Errorf("HookFuncName, MatchFuncName or SyscallFuncName is required")
	}

	var eventsFunc attachFunc = p.attachWithKprobeEvents
	var pmuFunc attachFunc = func() (*tracefsLink, error) {
		pfd, err := perfEventOpenPMU(p.HookFuncName, 0, -1, kprobe, p.isReturnProbe, 0)
		if err != nil {
			return nil, err
		}
		return &tracefsLink{perfEventLink: newPerfEventLink(pfd), Type: kprobe}, nil
	}

	pmuFirst := true
	startFunc, fallbackFunc := pmuFunc, eventsFunc
	// currently the perf event open ABI doesn't allow to specify the max active parameter
	if (p.KProbeMaxActive > 0 && p.isReturnProbe) || p.KprobeAttachMethod == AttachKprobeWithKprobeEvents {
		pmuFirst = false
		startFunc, fallbackFunc = eventsFunc, pmuFunc
	}

	var startErr, fallbackErr error
	var tl *tracefsLink
	if tl, startErr = startFunc(); startErr != nil {
		// do not fallback on tracefs events if PMU attach method is supported
		// and we got an actual error from it
		if pmuFirst && !errors.Is(startErr, ErrNotSupported) {
			return startErr
		}

		if tl, fallbackErr = fallbackFunc(); fallbackErr != nil {
			return errors.Join(startErr, fallbackErr)
		}
	}

	if err := attachPerfEvent(tl.perfEventLink, p.program); err != nil {
		_ = tl.Close()
		return fmt.Errorf("attach %s: %w", p.GetIdentificationPair(), err)
	}
	p.progLink = tl
	return nil
}

// PerfEventFD returns the associated perf event's fd for this Probe
func (p *Probe) PerfEventFD() (uint32, error) {
	v, ok := p.progLink.(*tracefsLink)
	if !ok {
		return 0, fmt.Errorf("Probe %q does not have a perf event link", p.programSpec.Name)
	}

	return v.fd.Value()
}

// attachWithKprobeEvents attaches the kprobe using the kprobes_events ABI
func (p *Probe) attachWithKprobeEvents() (*tracefsLink, error) {
	if p.kprobeHookPointNotExist {
		return nil, ErrKProbeHookPointNotExist
	}

	args := traceFsEventArgs{
		Type:         kprobe,
		ReturnProbe:  p.isReturnProbe,
		Symbol:       p.HookFuncName,
		UID:          p.UID,
		MaxActive:    p.KProbeMaxActive,
		AttachingPID: p.attachPID,
	}

	var kprobeID int
	var eventName string
	kprobeID, eventName, err := registerTraceFSEvent(args)
	if errors.Is(err, ErrProbeIDNotExist) {
		// The probe might have been loaded under a kernel generated event name. Clean up just in case.
		_ = unregisterTraceFSEvent(kprobe.eventsFilename(), getKernelGeneratedEventName(p.prefix(), p.HookFuncName))
		// fallback without KProbeMaxActive
		args.MaxActive = 0
		kprobeID, eventName, err = registerTraceFSEvent(args)
	}

	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			p.kprobeHookPointNotExist = true
		}
		return nil, fmt.Errorf("couldn't enable kprobe %s: %w", p.GetIdentificationPair(), err)
	}

	// create perf event fd
	pfd, err := perfEventOpenTracingEvent(kprobeID, -1)
	if err != nil {
		return nil, fmt.Errorf("couldn't open perf event fd for %s: %w", p.GetIdentificationPair(), err)
	}
	return &tracefsLink{perfEventLink: newPerfEventLink(pfd), Type: kprobe, EventName: eventName}, nil
}
