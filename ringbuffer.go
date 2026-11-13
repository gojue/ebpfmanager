package manager

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

type RingbufMapOptions struct {
	// Legacy fields retained for source compatibility. Ring buffers have no watermark.
	Watermark    int
	PerfErrChan  chan error
	PerfMapStats *PerfMapStats
	DumpHandler  func(*PerfMap, *Manager) string

	// ErrChan - Reader error channel
	ErrChan chan error

	// DataHandler - Callback function called when a new sample was retrieved from the perf
	// ring buffer.
	DataHandler func(CPU int, data []byte, ringBuffer *RingbufMap, manager *Manager)

	// RecordHandler - Callback function called when a new record was retrieved from the perf
	// ring buffer.
	RecordHandler func(record *ringbuf.Record, ringBuffer *RingbufMap, manager *Manager)

	// RecordGetter - if specified this getter will be used to get a new record
	RecordGetter func() *ringbuf.Record

	// TelemetryEnabled turns on telemetry about the usage of the ring buffer
	TelemetryEnabled bool
}

type RingbufMap struct {
	manager        *Manager
	ringReader     *ringbuf.Reader
	wgReader       sync.WaitGroup
	bufferSize     int
	usageTelemetry *atomic.Uint64

	// Map - A PerfMap has the same features as a normal Map
	Map
	RingbufMapOptions
}

// loadNewRingBuffer - Creates a new ring buffer map instance, loads it and sets up the ring buffer reader
func loadNewRingBuffer(spec *ebpf.MapSpec, options MapOptions, ringBufferOptions RingbufMapOptions) (*RingbufMap, error) {
	ringBuffer := RingbufMap{
		Map: Map{
			arraySpec:  spec,
			Name:       spec.Name,
			MapOptions: options,
		},
		RingbufMapOptions: ringBufferOptions,
	}

	var err error
	if ringBuffer.array, err = ebpf.NewMap(spec); err != nil {
		return nil, err
	}

	if ringBuffer.PinPath != "" {
		if err = ringBuffer.array.Pin(ringBuffer.PinPath); err != nil {
			return nil, fmt.Errorf("couldn't pin map %s at %s: %w", ringBuffer.Name, ringBuffer.PinPath, err)
		}
	}

	return &ringBuffer, nil
}

// init - Initialize a ring buffer
func (rb *RingbufMap) init(manager *Manager) error {
	rb.manager = manager
	if rb.ErrChan == nil {
		rb.ErrChan = rb.PerfErrChan
	}

	if rb.DataHandler == nil && rb.RecordHandler == nil {
		return fmt.Errorf("no DataHandler/RecordHandler set for %s", rb.Name)
	}

	if rb.TelemetryEnabled {
		rb.usageTelemetry = &atomic.Uint64{}
	}

	// Initialize the underlying map structure
	if err := rb.Map.init(); err != nil {
		return err
	}
	return nil
}

// Start - Starts fetching events on a perf ring buffer
func (rb *RingbufMap) Start() error {
	rb.stateLock.Lock()
	defer rb.stateLock.Unlock()
	if rb.state == running {
		return nil
	}
	if rb.state < initialized {
		return ErrMapNotInitialized
	}

	// Create and start the perf map
	var err error
	if rb.ringReader, err = ringbuf.NewReader(rb.array); err != nil {
		return err
	}
	rb.bufferSize = rb.ringReader.BufferSize()
	// Start listening for data
	rb.wgReader.Add(1)

	go func() {
		var record *ringbuf.Record
		var err error

		for {
			if rb.RecordGetter != nil {
				record = rb.RecordGetter()
			} else if rb.DataHandler != nil {
				record = new(ringbuf.Record)
			}

			if err = rb.ringReader.ReadInto(record); err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					rb.wgReader.Done()
					return
				}
				if errors.Is(err, ringbuf.ErrFlushed) {
					record.RawSample = record.RawSample[:0]
				} else {
					if rb.ErrChan != nil {
						rb.ErrChan <- err
					}
					continue
				}
			}

			if rb.usageTelemetry != nil {
				updateMaxTelemetry(rb.usageTelemetry, uint64(record.Remaining))
			}
			if rb.RecordHandler != nil {
				rb.RecordHandler(record, rb, rb.manager)
			} else if rb.DataHandler != nil {
				rb.DataHandler(0, record.RawSample, rb, rb.manager)
			}
		}
	}()

	rb.state = running
	return nil
}

// Flush unblocks the underlying reader and will cause the pending samples to be read
func (rb *RingbufMap) Flush() {
	rb.stateLock.Lock()
	defer rb.stateLock.Unlock()
	if rb.state != running {
		return
	}

	_ = rb.ringReader.Flush()
}

// Stop - Stops the ring buffer.
// Warning: Stop waits for the reader goroutine while holding stateLock.
// If the caller also holds manager.stateLock, and a handler callback needs
// manager.stateLock.RLock(), this will deadlock.
func (rb *RingbufMap) Stop(cleanup MapCleanupType) error {
	rb.stateLock.Lock()
	defer rb.stateLock.Unlock()
	if rb.state <= stopping {
		return nil
	}
	rb.state = stopping

	// close ring reader
	err := rb.ringReader.Close()

	rb.wgReader.Wait()

	// close underlying map
	if errTmp := rb.close(cleanup); errTmp != nil {
		if err == nil {
			err = errTmp
		} else {
			err = fmt.Errorf("%s: %w", err.Error(), errTmp)
		}
	}

	return err
}

// closeReader closes the ring reader to signal the reader goroutine to stop.
func (rb *RingbufMap) closeReader() error {
	rb.stateLock.Lock()
	defer rb.stateLock.Unlock()
	if rb.state <= stopping {
		return nil
	}
	rb.state = stopping
	return rb.ringReader.Close()
}

// cleanupMap closes the underlying map with the given cleanup type.
func (rb *RingbufMap) cleanupMap(cleanup MapCleanupType) error {
	rb.stateLock.Lock()
	defer rb.stateLock.Unlock()
	// check if map was already closed
	if rb.state == reset {
		return nil
	}
	return rb.close(cleanup)
}

// BufferSize returns the size in bytes of the ring buffer
func (rb *RingbufMap) BufferSize() int {
	rb.stateLock.Lock()
	defer rb.stateLock.Unlock()
	return rb.bufferSize
}

// Telemetry returns the usage telemetry
func (rb *RingbufMap) Telemetry() (usage uint64, ok bool) {
	rb.stateLock.Lock()
	defer rb.stateLock.Unlock()
	if rb.state < initialized || rb.usageTelemetry == nil {
		return 0, false
	}
	// reset to zero, so we return the max value between each collection
	return rb.usageTelemetry.Swap(0), true
}
