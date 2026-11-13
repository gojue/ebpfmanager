package manager

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// NewPerfRing - Creates a new perf ring and start listening for events.
// Use a MapRoute to make this map available to the programs of the manager.
func (m *Manager) NewPerfRingFromSpec(spec *ebpf.MapSpec, options MapOptions, perfMapOptions PerfMapOptions) (*ebpf.Map, error) {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	switch m.state {
	case reset, elfLoaded, stopping:
		return nil, ErrManagerNotInitialized
	case initialized, paused, running:
	}

	// check if the name of the new map is available
	_, exists, _ := m.getMap(spec.Name)
	if exists {
		return nil, ErrMapNameInUse
	}

	// Create new map and perf ring buffer reader
	perfMap, err := loadNewPerfMap(spec, options, perfMapOptions)
	if err != nil {
		return nil, err
	}

	// Setup perf buffer reader
	if err := perfMap.init(m); err != nil {
		return nil, err
	}

	// Start perf buffer reader
	if err := perfMap.Start(); err != nil {
		// clean up
		_ = perfMap.Stop(CleanInternal)
		return nil, err
	}

	// Add map to the list of perf ring managed by the manager
	m.PerfMaps = append(m.PerfMaps, perfMap)
	return perfMap.array, nil
}

// ClonePerfRing - Clone an existing perf map and create a new one with the same spec.
// Use a MapRoute to make this map available to the programs of the manager.
func (m *Manager) ClonePerfRing(name string, newName string, options MapOptions, perfMapOptions PerfMapOptions) (*ebpf.Map, error) {
	// Select map to clone
	oldSpec, exists, err := m.GetMapSpec(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("failed to clone maps/%s: couldn't find map: %w", name, ErrUnknownSection)
	}

	// Duplicate spec and create a new map
	spec := oldSpec.Copy()
	spec.Name = newName
	return m.NewPerfRingFromSpec(spec, options, perfMapOptions)
}
