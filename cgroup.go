package manager

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

// attachCGroup - Attaches the probe to a cgroup hook point
func (p *Probe) attachCGroup() error {
	var err error
	p.progLink, err = link.AttachCgroup(link.CgroupOptions{
		Path:    p.CGroupPath,
		Attach:  p.programSpec.AttachType,
		Program: p.program,
	})
	if err != nil {
		return fmt.Errorf("cgroup link %s: %w", p.CGroupPath, err)
	}
	return nil
}
