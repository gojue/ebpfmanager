package manager

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func (p *Probe) attachTracing() error {
	var err error
	if p.programSpec.AttachType == ebpf.AttachTraceIter {
		p.progLink, err = link.AttachIter(link.IterOptions{
			Program: p.program,
		})
	} else {
		p.progLink, err = link.AttachTracing(link.TracingOptions{
			Program:    p.program,
			AttachType: p.programSpec.AttachType,
		})
	}
	if err != nil {
		return fmt.Errorf("link tracing: %w", err)
	}
	return nil
}
