package manager

import (
	"debug/elf"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/link"
	"regexp"
)

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

// OpenAndListSymbols - Opens an elf file and extracts all its symbols
func OpenAndListSymbols(path string) (*elf.File, []elf.Symbol, error) {
	// open elf file
	f, err := elf.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't open elf file %s: %w", path, err)
	}
	defer f.Close()

	// Loop through all symbols
	syms, errSyms := f.Symbols()
	dynSyms, errDynSyms := f.DynamicSymbols()
	syms = append(syms, dynSyms...)

	if len(syms) == 0 {
		var err error
		if errSyms != nil {
			err = fmt.Errorf("failed to list symbols: %v", errSyms)
		}
		if errDynSyms != nil {
			err = fmt.Errorf("failed to list dynamic symbols: %v", errDynSyms)
		}
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("no symbols found")
	}
	return f, syms, nil
}

// findSymbolOffsets - Parses the provided file and returns the offsets of the symbols that match the provided pattern
func findSymbolOffsets(path string, pattern *regexp.Regexp) ([]elf.Symbol, error) {
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

// attachWithUprobeEvents attaches the uprobe using the uprobes_events ABI
func (p *Probe) attachWithUprobeEvents() (*tracefsLink, error) {
	args := traceFsEventArgs{
		Type:         uprobe,
		ReturnProbe:  p.isReturnProbe,
		Symbol:       p.HookFuncName, // only used for event naming
		Path:         p.BinaryPath,
		Offset:       p.uprobeFileOffset,
		UID:          p.UID,
		AttachingPID: p.attachPID,
	}

	var uprobeID int
	var eventName string
	uprobeID, eventName, err := registerTraceFSEvent(args)
	if err != nil {
		return nil, fmt.Errorf("couldn't enable uprobe %s: %w", p.GetIdentificationPair(), err)
	}

	pfd, err := perfEventOpenTracingEvent(uprobeID, p.PerfEventPID)
	if err != nil {
		return nil, fmt.Errorf("couldn't open perf event fd for %s: %w", p.GetIdentificationPair(), err)
	}
	return &tracefsLink{perfEventLink: newPerfEventLink(pfd), Type: uprobe, EventName: eventName}, nil
}

// attachUprobe - Attaches the probe to its Uprobe
func (p *Probe) resolveUprobeOffset() (uint64, error) {
	address := p.UAddress
	if address == 0 {
		var funcPattern string

		// find the offset of the first symbol matching the provided pattern
		if len(p.MatchFuncName) > 0 {
			funcPattern = p.MatchFuncName
		} else {
			funcPattern = fmt.Sprintf("^%s$", regexp.QuoteMeta(p.HookFuncName))
		}
		pattern, err := regexp.Compile(funcPattern)
		if err != nil {
			return 0, fmt.Errorf("failed to compile pattern %s: %w", funcPattern, err)
		}

		// Retrieve dynamic symbol offset
		offsets, err := findSymbolOffsets(p.BinaryPath, pattern)
		if err != nil {
			return 0, fmt.Errorf("couldn't find symbol matching %s in %s: %w", pattern.String(), p.BinaryPath, err)
		}
		address = offsets[0].Value
		p.HookFuncName = offsets[0].Name
	}
	if ^uint64(0)-address < p.UprobeOffset {
		return 0, fmt.Errorf("uprobe offset overflow")
	}
	return address + p.UprobeOffset, nil
}

func (p *Probe) attachUprobe() error {
	var err error
	p.uprobeFileOffset, err = p.resolveUprobeOffset()
	if err != nil {
		return err
	}
	// cilium links support bpffs pinning; keep the fork's LinkPinPath behavior.
	if p.LinkPinPath != "" {
		executable, err := link.OpenExecutable(p.BinaryPath)
		if err != nil {
			return err
		}
		opts := &link.UprobeOptions{Address: p.uprobeFileOffset, PID: p.PerfEventPID}
		if p.isReturnProbe {
			p.progLink, err = executable.Uretprobe(p.HookFuncName, p.program, opts)
		} else {
			p.progLink, err = executable.Uprobe(p.HookFuncName, p.program, opts)
		}
		return err
	}

	var eventsFunc attachFunc = p.attachWithUprobeEvents
	var pmuFunc attachFunc = func() (*tracefsLink, error) {
		pfd, err := perfEventOpenPMU(p.BinaryPath, int(p.uprobeFileOffset), p.PerfEventPID, uprobe, p.isReturnProbe, 0)
		if err != nil {
			return nil, err
		}
		return &tracefsLink{perfEventLink: newPerfEventLink(pfd), Type: uprobe}, nil
	}

	pmuFirst := true
	startFunc, fallbackFunc := pmuFunc, eventsFunc
	if p.UprobeAttachMethod == AttachWithProbeEvents {
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
