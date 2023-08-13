package manager

import (
	"errors"
	"fmt"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/gojue/ebpfmanager/kernel"
)

// RingbufMapOptions - Perf map specific options
type RingbufMapOptions struct {
	// Watermark - The reader will start processing samples once their sizes in the perf ring buffer
	// exceed this value. Must be smaller than PerfRingBufferSize. Defaults to the manager value if not set.
	Watermark int

	// PerfErrChan - Perf reader error channel
	PerfErrChan chan error

	// DataHandler - Callback function called when a new sample was retrieved from the perf
	// ring buffer.
	DataHandler func(CPU int, data []byte, perfMap *RingbufMap, manager *Manager)

	// PerfMapStats - Perf map statistics event like nr Read errors, lost samples,
	// RawSamples bytes count. Need to be initialized via manager.NewPerfMapStats()
	PerfMapStats *PerfMapStats

	// DumpHandler - Callback function called when manager.Dump() is called
	// and dump the current state (human readable)
	DumpHandler func(perfMap *PerfMap, manager *Manager) string
}

// RingbufMap -  ring buffer reader wrapper
type RingbufMap struct {
	manager       *Manager
	ringBufReader *ringbuf.Reader

	// Map - A PerfMap has the same features as a normal Map
	Map
	RingbufMapOptions
}

func (m *RingbufMap) Init(manager *Manager) error {
	kv, err := kernel.HostVersion()
	if err != nil {
		// nothing to do.
	}
	if kv < kernel.VersionCode(5, 8, 0) {
		return ErrRingbufNotSupported
	}
	m.manager = manager
	if m.DataHandler == nil {
		return fmt.Errorf("no DataHandler set for %s", m.Name)
	}

	if m.Watermark == 0 {
		m.Watermark = manager.options.DefaultWatermark
	}

	// Initialize the underlying map structure
	if err := m.Map.Init(manager); err != nil {
		return err
	}

	return nil
}

func (m *RingbufMap) Start() error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()

	if m.state == running {
		return nil
	}
	if m.state < initialized {
		return ErrMapNotInitialized
	}

	var err error
	m.ringBufReader, err = ringbuf.NewReader(m.array)
	if err != nil {
		return err
	}
	go func() {
		m.manager.wg.Add(1)
		for {
			record, err := m.ringBufReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					m.manager.wg.Done()
					return
				}
			}
			m.DataHandler(0, record.RawSample, m, m.manager)
		}
	}()
	m.state = running
	return nil
}

func (m *RingbufMap) Stop(cleanup MapCleanupType) error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()

	if m.state < running {
		return nil
	}
	err := m.ringBufReader.Close()
	m.state = initialized

	// close underlying map
	if errTmp := m.Map.close(cleanup); errTmp != nil {
		if err == nil {
			err = errTmp
		} else {
			err = fmt.Errorf("error%v, %s", errTmp, err.Error())
		}
	}
	return err
}
