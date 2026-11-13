package manager

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/link"
)

// attachRawTracepoint - Attaches the probe to its raw_tracepoint
func (p *Probe) attachRawTracepoint() error {
	if len(p.TracepointName) == 0 {
		traceGroup := strings.SplitN(p.programSpec.SectionName, "/", 2)
		if len(traceGroup) != 2 {
			return fmt.Errorf(`expected SEC("raw_tp/[name]") or SEC("raw_tracepoint/[name]") got %s: %w`, p.programSpec.SectionName, ErrSectionFormat)
		}
		p.TracepointName = traceGroup[1]
	}

	var err error
	p.progLink, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    p.TracepointName,
		Program: p.program,
	})
	if err != nil {
		return fmt.Errorf("link raw tracepoint: %w", err)
	}
	return nil
}
