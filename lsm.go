package manager

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

// attachLSM - Attaches the probe to its LSM hook point
func (p *Probe) attachLSM() error {
	var err error
	p.progLink, err = link.AttachLSM(link.LSMOptions{
		Program: p.program,
	})
	if err != nil {
		return fmt.Errorf("link lsm: %w", err)
	}
	return nil
}
