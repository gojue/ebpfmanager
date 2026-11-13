package manager

import "github.com/cilium/ebpf"

// NewRingBuffer - Creates a new ring buffer and start listening for events.
// Use a MapRoute to make this map available to the programs of the manager.
func (m *Manager) NewRingBuffer(spec *ebpf.MapSpec, options MapOptions, ringBufferOptions RingbufMapOptions) (*ebpf.Map, error) {
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

	// Create new map and ring buffer reader
	ringBuffer, err := loadNewRingBuffer(spec, options, ringBufferOptions)
	if err != nil {
		return nil, err
	}

	// Setup ring buffer reader
	if err := ringBuffer.init(m); err != nil {
		return nil, err
	}

	// Start perf buffer reader
	if err := ringBuffer.Start(); err != nil {
		// clean up
		_ = ringBuffer.Stop(CleanInternal)
		return nil, err
	}

	// Add map to the list of perf ring managed by the manager
	m.RingBuffers = append(m.RingBuffers, ringBuffer)
	return ringBuffer.array, nil
}
