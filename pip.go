package manager

import "fmt"

type ProbeIdentificationPair struct {
	// UID - (optional) this field can be used to identify your probes when the same eBPF program is used on multiple
	// hook points. Keep in mind that the pair (probe section, probe UID) needs to be unique
	// system-wide for the kprobes and uprobes registration to work.
	UID string

	// EbpfFuncName - Name of the main eBPF function of your eBPF program.
	EbpfFuncName string
}

func (pip ProbeIdentificationPair) String() string {
	return fmt.Sprintf("{UID:%s EbpfFuncName:%s}", pip.UID, pip.EbpfFuncName)
}

// RenameProbeIdentificationPair - Renames the probe identification pair of a probe
func (p *Probe) RenameProbeIdentificationPair(newID ProbeIdentificationPair) error {
	p.stateLock.Lock()
	defer p.stateLock.Unlock()
	if p.state >= paused {
		return fmt.Errorf("couldn't rename ProbeIdentificationPair of %s with %s: %w", p.GetIdentificationPair(), newID, ErrProbeRunning)
	}
	p.UID = newID.UID
	return nil
}

// RenameProbeIdentificationPair - Renames a probe identification pair. This change will propagate to all the features in
// the manager that will try to select the probe by its old ProbeIdentificationPair.
func (m *Manager) RenameProbeIdentificationPair(oldID ProbeIdentificationPair, newID ProbeIdentificationPair) error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()

	// sanity check: make sure the newID doesn't already exist
	for _, mProbe := range m.Probes {
		if mProbe.GetIdentificationPair() == newID {
			return ErrIdentificationPairInUse
		}
	}

	if oldID.EbpfFuncName != newID.EbpfFuncName {
		// edit the excluded sections
		for i, excludedFuncName := range m.options.ExcludedFunctions {
			if excludedFuncName == oldID.EbpfFuncName {
				m.options.ExcludedFunctions[i] = newID.EbpfFuncName
			}
		}
	}

	// edit the probe selectors
	for _, selector := range m.options.ActivatedProbes {
		selector.EditProbeIdentificationPair(oldID, newID)
	}

	// edit the probe
	p, ok := m.getProbe(oldID)
	if !ok {
		return ErrSymbolNotFound
	}
	return p.RenameProbeIdentificationPair(newID)
}
