package manager

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

// PerfMapOptions - Perf map specific options
type PerfMapOptions struct {
	// PerfRingBufferSize - Size in bytes of the perf ring buffer. Defaults to the manager value if not set.
	PerfRingBufferSize int

	// Watermark - The reader will start processing samples once their sizes in the perf ring buffer
	// exceed this value. Must be smaller than PerfRingBufferSize. Defaults to the manager value if not set.
	Watermark int

	// The number of events required in any per CPU buffer before
	// Read will process data. This is mutually exclusive with Watermark.
	// The default is zero, which means Watermark will take precedence.
	WakeupEvents int

	// PerfErrChan - Perf reader error channel
	PerfErrChan chan error

	// DataHandler - Callback function called when a new sample was retrieved from the perf
	// ring buffer.
	DataHandler func(CPU int, data []byte, perfMap *PerfMap, manager *Manager)

	// RecordHandler - Callback function called when a new record was retrieved from the perf
	// ring buffer.
	RecordHandler func(record *perf.Record, perfMap *PerfMap, manager *Manager)

	// LostHandler - Callback function called when one or more events where dropped by the kernel
	// because the perf ring buffer was full.
	LostHandler func(CPU int, count uint64, perfMap *PerfMap, manager *Manager)

	// RecordGetter - if specified this getter will be used to get a new record
	RecordGetter func() *perf.Record

	// TelemetryEnabled turns on telemetry about the usage of the perf ring buffer
	TelemetryEnabled bool
	PerfMapStats     *PerfMapStats
	DumpHandler      func(perfMap *PerfMap, manager *Manager) string
}

// PerfMap - Perf ring buffer reader wrapper
type PerfMap struct {
	manager        *Manager
	perfReader     *perf.Reader
	wgReader       sync.WaitGroup
	bufferSize     int
	usageTelemetry []*atomic.Uint64
	lostTelemetry  []*atomic.Uint64

	// Map - A PerfMap has the same features as a normal Map
	Map
	PerfMapOptions
}

// loadNewPerfMap - Creates a new perf map instance, loads it and sets up the perf ring buffer reader
func loadNewPerfMap(spec *ebpf.MapSpec, options MapOptions, perfOptions PerfMapOptions) (*PerfMap, error) {
	perfMap := PerfMap{
		Map: Map{
			arraySpec:  spec,
			Name:       spec.Name,
			MapOptions: options,
		},
		PerfMapOptions: perfOptions,
	}

	var err error
	if perfMap.array, err = ebpf.NewMap(spec); err != nil {
		return nil, err
	}

	if perfMap.PinPath != "" {
		if err = perfMap.array.Pin(perfMap.PinPath); err != nil {
			return nil, fmt.Errorf("couldn't pin map %s at %s: %w", perfMap.Name, perfMap.PinPath, err)
		}
	}

	return &perfMap, nil
}

// init - Initialize a map
func (m *PerfMap) init(manager *Manager) error {
	m.manager = manager

	if m.DataHandler == nil && m.RecordHandler == nil {
		return fmt.Errorf("no DataHandler/RecordHandler set for %s", m.Name)
	}

	// Set default values if not already set
	if m.PerfRingBufferSize == 0 {
		m.PerfRingBufferSize = manager.options.DefaultPerfRingBufferSize
	}
	if m.WakeupEvents == 0 && m.Watermark == 0 {
		m.Watermark = manager.options.DefaultWatermark
	}

	if m.TelemetryEnabled {
		nCPU := m.array.MaxEntries()
		m.usageTelemetry = make([]*atomic.Uint64, nCPU)
		m.lostTelemetry = make([]*atomic.Uint64, nCPU)
		for cpu := range m.usageTelemetry {
			m.usageTelemetry[cpu] = &atomic.Uint64{}
			m.lostTelemetry[cpu] = &atomic.Uint64{}
		}
	}

	// Initialize the underlying map structure
	if err := m.Map.init(); err != nil {
		return err
	}
	return nil
}

// Start - Starts fetching events on a perf ring buffer
func (m *PerfMap) Start() error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	if m.state == running {
		return nil
	}
	if m.state < initialized {
		return ErrMapNotInitialized
	}

	// Create and start the perf map
	var err error
	opt := perf.ReaderOptions{
		Watermark:    m.Watermark,
		WakeupEvents: m.WakeupEvents,
	}
	if m.perfReader, err = perf.NewReaderWithOptions(m.array, m.PerfRingBufferSize, opt); err != nil {
		return err
	}
	m.bufferSize = m.perfReader.BufferSize()

	m.wgReader.Add(1)

	// Start listening for data
	go func() {
		record := &perf.Record{}
		var err error

		for {
			if m.RecordGetter != nil {
				record = m.RecordGetter()
			} else if m.DataHandler != nil {
				record = new(perf.Record)
			}

			if err = m.perfReader.ReadInto(record); err != nil {
				if errors.Is(err, perf.ErrClosed) {
					m.wgReader.Done()
					return
				}
				// all records post-wakeup have been read, send sentinel empty record
				if errors.Is(err, perf.ErrFlushed) {
					record.RawSample = record.RawSample[:0]
				} else {
					if m.PerfMapStats != nil {
						m.PerfMapStats.ReadErrors++
					}
					if m.PerfErrChan != nil {
						m.PerfErrChan <- err
					}
					continue
				}
			}

			if record.LostSamples > 0 {
				if m.PerfMapStats != nil {
					m.PerfMapStats.LostSamples[record.CPU] += record.LostSamples
				}
				if m.lostTelemetry != nil && record.CPU < len(m.lostTelemetry) {
					m.lostTelemetry[record.CPU].Add(record.LostSamples)
					// force usage to max because a sample was lost
					updateMaxTelemetry(m.usageTelemetry[record.CPU], uint64(m.bufferSize))
				}
				if m.LostHandler != nil {
					m.LostHandler(record.CPU, record.LostSamples, m, m.manager)
				}
				continue
			}

			if m.usageTelemetry != nil && record.CPU < len(m.usageTelemetry) {
				updateMaxTelemetry(m.usageTelemetry[record.CPU], uint64(record.Remaining))
			}
			if m.PerfMapStats != nil {
				m.PerfMapStats.RawSamples[record.CPU] += uint64(len(record.RawSample))
			}
			if m.RecordHandler != nil {
				m.RecordHandler(record, m, m.manager)
			} else if m.DataHandler != nil {
				m.DataHandler(record.CPU, record.RawSample, m, m.manager)
			}
		}
	}()

	m.state = running
	return nil
}

// Flush unblocks the underlying reader and will cause the pending samples to be read
func (m *PerfMap) Flush() {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	if m.state != running {
		return
	}

	_ = m.perfReader.Flush()
}

// Stop - Stops the perf ring buffer.
// Warning: Stop waits for the reader goroutine while holding stateLock.
// If the caller also holds manager.stateLock, and a handler callback needs
// manager.stateLock.RLock(), this will deadlock.
func (m *PerfMap) Stop(cleanup MapCleanupType) error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	if m.state <= stopping {
		return nil
	}
	m.state = stopping

	// close perf reader
	err := m.perfReader.Close()

	m.wgReader.Wait()

	// close underlying map
	if errTmp := m.close(cleanup); errTmp != nil {
		if err == nil {
			err = errTmp
		} else {
			err = fmt.Errorf("%s: %w", err.Error(), errTmp)
		}
	}

	return err
}

// closeReader closes the perf reader to signal the reader goroutine to stop.
func (m *PerfMap) closeReader() error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	if m.state <= stopping {
		return nil
	}
	m.state = stopping
	return m.perfReader.Close()
}

// cleanupMap closes the underlying map with the given cleanup type.
func (m *PerfMap) cleanupMap(cleanup MapCleanupType) error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	// check if map was already closed
	if m.state == reset {
		return nil
	}
	return m.close(cleanup)
}

// Pause - Pauses a perf ring buffer reader
func (m *PerfMap) Pause() error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	if m.state < running {
		return ErrMapNotRunning
	}
	if err := m.perfReader.Pause(); err != nil {
		return err
	}
	m.state = paused
	return nil
}

// Resume - Resumes a perf ring buffer reader
func (m *PerfMap) Resume() error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	if m.state < paused {
		return ErrMapNotRunning
	}
	if err := m.perfReader.Resume(); err != nil {
		return err
	}
	m.state = running
	return nil
}

// BufferSize is the size in bytes of each per-CPU buffer
func (m *PerfMap) BufferSize() int {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	return m.bufferSize
}

// Telemetry returns the usage and lost telemetry
func (m *PerfMap) Telemetry() (usage []uint64, lost []uint64) {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	if m.state < initialized || m.usageTelemetry == nil || m.lostTelemetry == nil {
		return nil, nil
	}
	usage = make([]uint64, len(m.usageTelemetry))
	lost = make([]uint64, len(m.lostTelemetry))
	for cpu := range m.usageTelemetry {
		// reset to zero, so we return the max value between each collection
		usage[cpu] = m.usageTelemetry[cpu].Swap(0)
		lost[cpu] = m.lostTelemetry[cpu].Swap(0)
	}
	return
}

func updateMaxTelemetry(a *atomic.Uint64, val uint64) {
	for {
		oldVal := a.Load()
		if val <= oldVal {
			return
		}
		if a.CompareAndSwap(oldVal, val) {
			return
		}
	}
}
