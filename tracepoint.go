package manager

import (
	"fmt"
	"strings"
)

// attachTracepoint - Attaches the probe to its tracepoint
func (p *Probe) attachTracepoint() error {
	// Parse section
	if len(p.TracepointCategory) == 0 || len(p.TracepointName) == 0 {
		traceGroup := strings.SplitN(p.programSpec.SectionName, "/", 3)
		if len(traceGroup) != 3 {
			return fmt.Errorf("expected SEC(\"tracepoint/[category]/[name]\") got %s: %w", p.programSpec.SectionName, ErrSectionFormat)
		}
		p.TracepointCategory = traceGroup[1]
		p.TracepointName = traceGroup[2]
	}

	// Get the ID of the tracepoint to activate
	tracepointID, err := GetTracepointID(p.TracepointCategory, p.TracepointName)
	if err != nil {
		return fmt.Errorf("couldn't activate tracepoint %s: %w", p.GetIdentificationPair(), err)
	}

	// Hook the eBPF program to the tracepoint
	fd, err := perfEventOpenTracingEvent(tracepointID, -1)
	if err != nil {
		return fmt.Errorf("couldn't enable tracepoint %s: %w", p.GetIdentificationPair(), err)
	}
	pe := newPerfEventLink(fd)
	if err := attachPerfEvent(pe, p.program); err != nil {
		_ = pe.Close()
		return fmt.Errorf("attach %s: %w", p.GetIdentificationPair(), err)
	}
	p.progLink = pe
	return nil
}
