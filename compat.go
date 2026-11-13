package manager

import (
	"debug/elf"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/gojue/ebpfmanager/tracefs"
	"golang.org/x/sys/unix"
	"os"
	"regexp"
	"strings"
)

// Compatibility with the public API used by eCapture and existing fork clients.
type RingBuffer = RingbufMap
type RingBufferOptions = RingbufMapOptions

const (
	UnknownProbeType = ""
	ProbeType        = "p"
	RetProbeType     = "r"
)

var (
	ErrUnknownMatchFuncName = ErrUnknownSectionOrFuncName
	ErrUnknownMatchFuncSpec = ErrUnknownSectionOrFuncName
	ErrUnknownMap           = ErrUnknownSection
	ErrLoopbackDisabled     = errors.New("loopback is disabled")
)

func (p *Probe) GetIdentificationPair() ProbeIdentificationPair {
	return ProbeIdentificationPair{UID: p.UID, EbpfFuncName: p.EbpfFuncName}
}
func (p *Probe) IdentificationPairMatches(id ProbeIdentificationPair) bool {
	return p.GetIdentificationPair().Matches(id)
}
func (pip ProbeIdentificationPair) Matches(id ProbeIdentificationPair) bool { return pip == id }
func (p *Probe) GetEBPFFuncName() string                                    { return p.GetEbpfFuncName() }
func (p *Probe) Init(m *Manager) error                                      { return p.init(m) }
func (p *Probe) InitWithOptions(m *Manager, manualLoadNeeded, checkPin bool) error {
	return p.initWithOptions(m, manualLoadNeeded, checkPin)
}

func (p *Probe) normalizeLegacyFields() error {
	if p.IfIndex == 0 {
		p.IfIndex = int(p.Ifindex)
	}
	if p.IfName == "" {
		p.IfName = p.Ifname
	}
	if p.IfIndexNetns == 0 {
		p.IfIndexNetns = p.IfindexNetns
	}
	if p.IfIndexNetns != 0 && p.IfIndexNetnsID == 0 {
		var st unix.Stat_t
		if err := unix.Fstat(int(p.IfIndexNetns), &st); err != nil {
			return fmt.Errorf("network namespace: %w", err)
		}
		p.IfIndexNetnsID = uint32(st.Ino)
	}
	if p.PerfEventPID == 0 {
		p.PerfEventPID = p.AttachPID
	}
	return nil
}

func (m *Manager) DetachHook(ebpfFuncName, uid string) error {
	return m.DetachHookByID(ProbeIdentificationPair{UID: uid, EbpfFuncName: ebpfFuncName})
}
func (m *Manager) NewMap(spec ebpf.MapSpec, options MapOptions) (*ebpf.Map, error) {
	return m.NewMapFromSpec(&spec, options)
}
func (m *Manager) NewPerfRing(spec ebpf.MapSpec, options MapOptions, perfOptions PerfMapOptions) (*ebpf.Map, error) {
	return m.NewPerfRingFromSpec(&spec, options, perfOptions)
}
func (m *Map) Init(manager *Manager) error {
	array, found, err := manager.GetMap(m.Name)
	if err != nil {
		return err
	}
	if !found {
		return ErrUnknownMap
	}
	spec, found, err := manager.GetMapSpec(m.Name)
	if err != nil {
		return err
	}
	if !found {
		return ErrUnknownMap
	}
	m.array, m.arraySpec = array, spec
	return m.init()
}
func (m *PerfMap) Init(manager *Manager) error {
	if m.array == nil {
		if err := m.Map.Init(manager); err != nil {
			return err
		}
		m.state = reset
	}
	return m.init(manager)
}
func (m *RingbufMap) Init(manager *Manager) error {
	if m.array == nil {
		if err := m.Map.Init(manager); err != nil {
			return err
		}
		m.state = reset
	}
	return m.init(manager)
}
func ConcatErrors(a, b error) error { return errors.Join(a, b) }
func GenerateEventName(probeType, funcName, uid string, pid int) (string, error) {
	return generateEventName(probeType, funcName, uid, pid)
}
func FindSymbolOffsets(path string, pattern *regexp.Regexp) ([]elf.Symbol, error) {
	return findSymbolOffsets(path, pattern)
}
func TracefsRoot() (string, error)                { return tracefs.Root() }
func TracefsReadFile(name string) ([]byte, error) { return tracefs.ReadFile(name) }
func TracefsOpen(name string) (*os.File, error)   { return tracefs.Open(name) }
func TracefsOpenFile(name string, flags int, mode os.FileMode) (*os.File, error) {
	return tracefs.OpenFile(name, flags, mode)
}

// PerfMapStats contain perf map read/errors statistics
// including per CPU map bytes and lost bytes
type PerfMapStats struct {
	ReadErrors  uint64
	RawSamples  map[int]uint64
	LostSamples map[int]uint64
}

// NewPerfMapStats create/enable counting the perf map statistics performance/debug information
func NewPerfMapStats() *PerfMapStats {
	return &PerfMapStats{
		RawSamples:  make(map[int]uint64),
		LostSamples: make(map[int]uint64),
	}
}

func (new *PerfMapStats) Diff(old *PerfMapStats) (diff *PerfMapStats) {
	if new == nil || old == nil {
		return nil
	}
	diff = NewPerfMapStats()
	diff.ReadErrors = new.ReadErrors - old.ReadErrors

	for cpu := range new.RawSamples {
		rawOld, found := old.RawSamples[cpu]
		if !found {
			rawOld = 0
		}
		diff.RawSamples[cpu] = new.RawSamples[cpu] - rawOld
	}
	for cpu := range new.LostSamples {
		lostOld, found := old.LostSamples[cpu]
		if !found {
			lostOld = 0
		}
		diff.LostSamples[cpu] = new.LostSamples[cpu] - lostOld
	}
	return diff
}

func (m *Manager) DumpMaps(maps ...string) (string, error) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()

	if m.collection == nil || m.state < initialized {
		return "", ErrManagerNotInitialized
	}

	var mapsToDump map[string]struct{}
	if len(maps) > 0 {
		mapsToDump = make(map[string]struct{})
		for _, m := range maps {
			mapsToDump[m] = struct{}{}
		}
	}
	needDump := func(name string) bool {
		if mapsToDump == nil {
			// dump all maps
			return true
		}
		_, found := mapsToDump[name]
		return found
	}

	var output strings.Builder
	// Look in the list of maps
	for _, managerMap := range m.Maps {
		if managerMap.DumpHandler != nil && needDump(managerMap.Name) {
			output.WriteString(managerMap.DumpHandler(managerMap, m))
		}
	}
	// Look in the list of perf maps
	for _, perfMap := range m.PerfMaps {
		if perfMap.DumpHandler != nil && needDump(perfMap.Name) {
			output.WriteString(perfMap.DumpHandler(perfMap, m))
		}
	}
	return output.String(), nil
}

// Editor retains the exported instruction editor API of the fork.
type Editor = editor

func Edit(insns *asm.Instructions) *Editor { return newEditor(insns) }
func IsUnreferencedSymbol(err error) bool  { return isUnreferencedSymbol(err) }
