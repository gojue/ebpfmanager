package manager

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/rlimit"
)

// FunctionExcluder - An interface for types that can be used for `AdditionalExcludedFunctionCollector`
type FunctionExcluder interface {
	// ShouldExcludeFunction - Returns true if the function should be excluded
	ShouldExcludeFunction(name string, prog *ebpf.ProgramSpec) bool
	// CleanCaches - Is called when the manager is done with the excluder (for memory reclaiming for example)
	CleanCaches()
}

// Options - Options of a Manager. These options define how a manager should be initialized.
type Options struct {
	// ActivatedProbes - List of the probes that should be activated, identified by their identification string.
	// If the list is empty, all probes will be activated.
	ActivatedProbes []ProbesSelector

	// KeepUnmappedProgramSpecs - Defines if the manager should keep unmapped ProgramSpec instances in the collection.
	// Enable this feature if you're going to clone one of these ProgramSpec.
	KeepUnmappedProgramSpecs bool
	// DiscardProgramSpecs opts into upstream instruction cleanup. By default,
	// retain specs so existing CloneProgram callers continue to work.
	DiscardProgramSpecs bool

	// ExcludedFunctions - A list of functions that should not even be verified. This list overrides the ActivatedProbes
	// list: since the excluded sections aren't loaded in the kernel, all the probes using those sections will be
	// deactivated.
	ExcludedFunctions []string
	// ExcludedEbpfFuncs is the fork spelling of ExcludedFunctions.
	ExcludedEbpfFuncs []string
	// ExcludedSections is retained for compatibility; prefer function names.
	ExcludedSections []string
	RLimit           *unix.Rlimit

	// AdditionalExcludedFunctionCollector - A dynamic function excluder, allowing to exclude functions with a callback.
	AdditionalExcludedFunctionCollector FunctionExcluder

	// ExcludedMaps - A list of maps that should not be created.
	ExcludedMaps []string

	// ConstantsEditor - Post-compilation constant edition. See ConstantEditor for more.
	ConstantEditors []ConstantEditor

	// MapSpecEditor - Pre-loading MapSpec editors.
	MapSpecEditors map[string]MapSpecEditor

	// VerifierOptions - Defines the log level of the verifier and the size of its log buffer. Set to 0 to disable
	// logging and 1 to get a verbose output of the error. Increase the buffer size if the output is truncated.
	VerifierOptions ebpf.CollectionOptions

	// MapEditors - External map editor. The provided eBPF maps will overwrite the maps of the Manager if their names
	// match.
	// This is particularly useful to share maps across Managers (and therefore across isolated eBPF programs), without
	// having to use the MapRouter indirection. However, this technique only works before the eBPF programs are loaded,
	// and therefore before the Manager is started. The keys of the map are the names of the maps to edit, as defined
	// in their sections SEC("maps/[name]").
	MapEditors map[string]*ebpf.Map

	// MapEditorsIgnoreMissingMaps - If MapEditorsIgnoreMissingMaps is set to true, the map edition process will return an
	// error if a map was missing in at least one program
	MapEditorsIgnoreMissingMaps bool

	// MapRouter - External map routing. See MapRoute for more.
	MapRouter []MapRoute

	// InnerOuterMapSpecs - Defines the mapping between inner and outer maps. See InnerOuterMapSpec for more.
	InnerOuterMapSpecs []InnerOuterMapSpec

	// TailCallRouter - External tail call routing. See TailCallRoute for more.
	TailCallRouter []TailCallRoute

	// SymFile - Kernel symbol file. If not provided, the default `/proc/kallsyms` will be used.
	SymFile string

	// PerfRingBufferSize - Manager-level default value for the perf ring buffers. Defaults to the size of 1 page
	// on the system. See PerfMap.PerfRingBuffer for more.
	DefaultPerfRingBufferSize int

	// Watermark - Manager-level default value for the watermarks of the perf ring buffers.
	// See PerfMap.Watermark for more.
	DefaultWatermark int

	// DefaultKProbeMaxActive - Manager-level default value for the kprobe max active parameter.
	// See Probe.MaxActive for more.
	DefaultKProbeMaxActive int

	// DefaultKprobeAttachMethod - Manager-level default value for the Kprobe attach method. Defaults to AttachKprobeWithPerfEventOpen if unset.
	DefaultKprobeAttachMethod KprobeAttachMethod

	// DefaultUprobeAttachMethod - Manager-level default value for the Uprobe attach method. Defaults to AttachWithPerfEventOpen if unset.
	DefaultUprobeAttachMethod AttachMethod

	// ProbeRetry - Defines the number of times that a probe will retry to attach / detach on error.
	DefaultProbeRetry uint

	// ProbeRetryDelay - Defines the delay to wait before a probe should retry to attach / detach on error.
	DefaultProbeRetryDelay time.Duration

	// RemoveRlimit - The maps & programs provided to the manager might exceed the maximum allowed memory lock.
	// `RLIMIT_MEMLOCK` If a limit is provided here it will be applied when the manager is initialized.
	RemoveRlimit bool

	// KeepKernelBTF - Defines if the kernel BTF used while loading programs should be cleaned up once the manager is done
	// using them. This governs both VerifierOptions.Programs.KernelTypes and the shared VerifierOptions.Cache. By default,
	// the manager will clean both up after Start() to save up space: otherwise a long-lived manager keeps the parsed
	// kernel BTF (vmlinux) pinned for the whole process lifetime, even though it is only needed while loading programs.
	// DISCLAIMER: if your program uses "manager.CloneProgram", you might want to enable "KeepKernelBTF", as cloning
	// reloads a program and needs "KernelTypes" for its CO-RE relocations. As a workaround, you can also try to strip as
	// much as possible the content of "KernelTypes" to reduce the memory overhead.
	KeepKernelBTF bool

	// SkipPerfMapReaderStartup - Perf maps whose name is set to true with this option will not have their reader goroutine started when calling the manager.Start() function.
	// PerfMap.Start() can then be used to start reading events from the corresponding PerfMap.
	SkipPerfMapReaderStartup map[string]bool

	// SkipRingbufferReaderStartup - Ringbuffer maps whose name is set to true with this option will not have their reader goroutine started when calling the manager.Start() function.
	// RingbufMap.Start() can then be used to start reading events from the corresponding RingbufMap.
	SkipRingbufferReaderStartup map[string]bool

	// BypassEnabled controls whether program bypass is enabled for this manager
	BypassEnabled bool
}

// InstructionPatcherFunc - A function that patches the instructions of a program
type InstructionPatcherFunc func(m *Manager) error

// Manager - Helper structure that manages multiple eBPF programs and maps
type Manager struct {
	collectionSpec     *ebpf.CollectionSpec
	collection         *ebpf.Collection
	options            Options
	netlinkSocketCache *netlinkSocketCache
	state              state
	stateLock          sync.RWMutex
	bypassIndexes      map[string]uint32
	maxBypassIndex     uint32

	// Probes - List of probes handled by the manager
	Probes []*Probe

	// Maps - List of maps handled by the manager. PerfMaps should not be defined here, but instead in the PerfMaps
	// section
	Maps []*Map

	// PerfMaps - List of perf ring buffers handled by the manager
	PerfMaps []*PerfMap

	// RingBuffers - List of perf ring buffers handled by the manager
	RingBuffers []*RingbufMap
	RingbufMaps []*RingbufMap

	// DumpHandler - Callback function called when manager.DumpMaps() is called
	// and dump the current state (human-readable)
	DumpHandler func(w io.Writer, manager *Manager, mapName string, currentMap *ebpf.Map)

	// InstructionPatchers - Callback functions called before loading probes, to
	// provide user the ability to perform last minute instruction patching.
	InstructionPatchers []InstructionPatcherFunc
}

// DumpMaps - Write in the w writer argument human-readable info about eBPF maps
// Dumps the set of maps provided, otherwise dumping all maps with a DumpHandler set.
func (m *Manager) DumpMapsTo(w io.Writer, maps ...string) error {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	switch m.state {
	case reset, elfLoaded:
		return ErrManagerNotInitialized
	case initialized, stopping, paused, running:
	}
	if m.collection == nil {
		return ErrManagerNotInitialized
	}

	if m.DumpHandler == nil {
		return nil
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

	// Look in the list of maps
	for mapName, currentMap := range m.collection.Maps {
		if needDump(mapName) {
			m.DumpHandler(w, m, mapName, currentMap)
		}
	}
	return nil
}

// getMap - Thread unsafe version of GetMap
func (m *Manager) getMap(name string) (*ebpf.Map, bool, error) {
	eBPFMap, ok := m.collection.Maps[name]
	if ok {
		return eBPFMap, true, nil
	}
	// Look in the list of maps
	for _, managerMap := range m.Maps {
		if managerMap.Name == name {
			return managerMap.array, true, nil
		}
	}
	if perfMap, found := m.getPerfMap(name); found {
		return perfMap.array, true, nil
	}
	if ringBuffer, found := m.getRingBuffer(name); found {
		return ringBuffer.array, true, nil
	}
	return nil, false, nil
}

// GetMap - Return a pointer to the requested eBPF map
// name: name of the map, as defined by its section SEC("maps/[name]")
func (m *Manager) GetMap(name string) (*ebpf.Map, bool, error) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	switch m.state {
	case reset, elfLoaded:
		return nil, false, ErrManagerNotInitialized
	case initialized, stopping, paused, running:
	}
	if m.collection == nil {
		return nil, false, ErrManagerNotInitialized
	}
	return m.getMap(name)
}

// GetMaps - Return the list of eBPF maps in the manager
func (m *Manager) GetMaps() (map[string]*ebpf.Map, error) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	switch m.state {
	case reset, elfLoaded:
		return nil, ErrManagerNotInitialized
	case initialized, stopping, paused, running:
	}
	if m.collection == nil {
		return nil, ErrManagerNotInitialized
	}

	output := make(map[string]*ebpf.Map, len(m.collection.Maps))
	for section, m := range m.collection.Maps {
		output[section] = m
	}
	return output, nil
}

// getMapSpec - Thread unsafe version of GetMapSpec
func (m *Manager) getMapSpec(name string) (*ebpf.MapSpec, bool, error) {
	eBPFMap, ok := m.collectionSpec.Maps[name]
	if ok {
		return eBPFMap, true, nil
	}
	// Look in the list of maps
	for _, managerMap := range m.Maps {
		if managerMap.Name == name {
			return managerMap.arraySpec, true, nil
		}
	}
	if perfMap, found := m.getPerfMap(name); found {
		return perfMap.arraySpec, true, nil
	}
	if ringBuffer, found := m.getRingBuffer(name); found {
		return ringBuffer.arraySpec, true, nil
	}
	return nil, false, nil
}

// GetMapSpec - Return a pointer to the requested eBPF MapSpec. This is useful when duplicating a map.
func (m *Manager) GetMapSpec(name string) (*ebpf.MapSpec, bool, error) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	switch m.state {
	case reset:
		return nil, false, ErrManagerNotELFLoaded
	case elfLoaded, initialized, stopping, paused, running:
	}
	if m.collectionSpec == nil {
		return nil, false, ErrManagerNotELFLoaded
	}
	return m.getMapSpec(name)
}

// getPerfMap - Thread unsafe version of GetPerfMap
func (m *Manager) getPerfMap(name string) (*PerfMap, bool) {
	for _, perfMap := range m.PerfMaps {
		if perfMap.Name == name {
			return perfMap, true
		}
	}
	return nil, false
}

// GetPerfMap - Select a perf map by its name
func (m *Manager) GetPerfMap(name string) (*PerfMap, bool) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	return m.getPerfMap(name)
}

// getRingBuffer - Thread unsafe version of GetRingBuffer
func (m *Manager) getRingBuffer(name string) (*RingbufMap, bool) {
	for _, ringBuffer := range m.RingBuffers {
		if ringBuffer.Name == name {
			return ringBuffer, true
		}
	}
	return nil, false
}

// GetRingBuffer - Select a ring buffer by its name
func (m *Manager) GetRingBuffer(name string) (*RingbufMap, bool) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	return m.getRingBuffer(name)
}

// getProgram - Thread unsafe version of GetProgram
func (m *Manager) getProgram(id ProbeIdentificationPair) ([]*ebpf.Program, bool, error) {
	var programs []*ebpf.Program
	if id.UID == "" {
		for _, probe := range m.Probes {
			if probe.EbpfFuncName == id.EbpfFuncName {
				programs = append(programs, probe.program)
			}
		}
		if len(programs) > 0 {
			return programs, true, nil
		}
		prog, ok := m.collection.Programs[id.EbpfFuncName]
		return []*ebpf.Program{prog}, ok, nil
	}
	for _, probe := range m.Probes {
		if probe.GetIdentificationPair() == id {
			return []*ebpf.Program{probe.program}, true, nil
		}
	}
	return programs, false, nil
}

// GetProgram - Return a pointer to the requested eBPF program
// section: section of the program, as defined by its section SEC("[section]")
// id: unique identifier given to a probe. If UID is empty, then all the programs matching the provided section are
// returned.
func (m *Manager) GetProgram(id ProbeIdentificationPair) ([]*ebpf.Program, bool, error) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	switch m.state {
	case reset, elfLoaded:
		return nil, false, ErrManagerNotInitialized
	case initialized, stopping, paused, running:
	}
	if m.collection == nil {
		return nil, false, ErrManagerNotInitialized
	}
	return m.getProgram(id)
}

// GetPrograms - Return the list of eBPF programs in the manager
func (m *Manager) GetPrograms() (map[string]*ebpf.Program, error) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	switch m.state {
	case reset, elfLoaded:
		return nil, ErrManagerNotInitialized
	case initialized, stopping, paused, running:
	}
	if m.collection == nil {
		return nil, ErrManagerNotInitialized
	}

	return maps.Clone(m.collection.Programs), nil
}

// GetMapSpecs - Return the list of eBPF map specs in the manager
func (m *Manager) GetMapSpecs() (map[string]*ebpf.MapSpec, error) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	switch m.state {
	case reset:
		return nil, ErrManagerNotELFLoaded
	case elfLoaded, initialized, stopping, paused, running:
	}
	if m.collectionSpec == nil {
		return nil, ErrManagerNotELFLoaded
	}

	return maps.Clone(m.collectionSpec.Maps), nil
}

// GetProgramSpecs - Return the list of eBPF program specs in the manager
func (m *Manager) GetProgramSpecs() (map[string]*ebpf.ProgramSpec, error) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	switch m.state {
	case reset:
		return nil, ErrManagerNotELFLoaded
	case elfLoaded, initialized, stopping, paused, running:
	}
	if m.collectionSpec == nil {
		return nil, ErrManagerNotELFLoaded
	}

	return maps.Clone(m.collectionSpec.Programs), nil
}

// getProgramSpec - Thread unsafe version of GetProgramSpec
func (m *Manager) getProgramSpec(id ProbeIdentificationPair) ([]*ebpf.ProgramSpec, bool, error) {
	var programs []*ebpf.ProgramSpec
	if id.UID == "" {
		for _, probe := range m.Probes {
			if probe.EbpfFuncName == id.EbpfFuncName && probe.programSpec != nil {
				programs = append(programs, probe.programSpec)
			}
		}
		if len(programs) > 0 {
			return programs, true, nil
		}
		prog, ok := m.collectionSpec.Programs[id.EbpfFuncName]
		return []*ebpf.ProgramSpec{prog}, ok, nil
	}
	for _, probe := range m.Probes {
		if probe.GetIdentificationPair() == id {
			return []*ebpf.ProgramSpec{probe.programSpec}, true, nil
		}
	}
	return programs, false, nil
}

// GetProgramSpec - Return a pointer to the requested eBPF program spec
// section: section of the program, as defined by its section SEC("[section]")
// id: unique identifier given to a probe. If UID is empty, then the original program spec with the right section in the
// collection spec (if found) is return
func (m *Manager) GetProgramSpec(id ProbeIdentificationPair) ([]*ebpf.ProgramSpec, bool, error) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	switch m.state {
	case reset:
		return nil, false, ErrManagerNotELFLoaded
	case elfLoaded, initialized, stopping, paused, running:
	}
	if m.collectionSpec == nil {
		return nil, false, ErrManagerNotELFLoaded
	}
	return m.getProgramSpec(id)
}

// getProbe - Thread unsafe version of GetProbe
func (m *Manager) getProbe(id ProbeIdentificationPair) (*Probe, bool) {
	for _, managerProbe := range m.Probes {
		if managerProbe.GetIdentificationPair() == id {
			return managerProbe, true
		}
	}
	return nil, false
}

// GetProbes returns a copy of the Probes list
func (m *Manager) GetProbes() []*Probe {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()

	return slices.Clone(m.Probes)
}

// GetProbe - Select a probe by its section and UID
func (m *Manager) GetProbe(id ProbeIdentificationPair) (*Probe, bool) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	return m.getProbe(id)
}

// LoadELF loads the collection spec from the provided ELF reader
func (m *Manager) LoadELF(elf io.ReaderAt) error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	switch m.state {
	case reset:
		return m.loadELF(elf)
	case elfLoaded, initialized, stopping, paused, running:
		return ErrManagerELFLoaded
	}
	return nil
}

func (m *Manager) loadELF(elf io.ReaderAt) error {
	// Load the provided elf buffer
	var err error
	m.collectionSpec, err = ebpf.LoadCollectionSpecFromReader(elf)
	if err != nil {
		return err
	}
	m.state = elfLoaded
	return nil
}

// Init - Initialize the manager.
// elf: reader containing the eBPF bytecode, must be nil if LoadELF already called
func (m *Manager) Init(elf io.ReaderAt) error {
	return m.InitWithOptions(elf, Options{})
}

// InitWithOptions - Initialize the manager.
// elf: reader containing the eBPF bytecode, must be nil if LoadELF already called
// options: options provided to the manager to configure its initialization
func (m *Manager) InitWithOptions(elf io.ReaderAt, options Options) error {
	if err := m.initState(elf, options); err != nil {
		return err
	}

	if err := m.postInit(m.options); err != nil {
		m.stateLock.Lock()
		m.state = reset
		m.stateLock.Unlock()
		return err
	}

	return nil
}

func (m *Manager) initState(elf io.ReaderAt, options Options) error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()

	switch m.state {
	case stopping, paused, running:
		return ErrManagerRunning
	case reset, elfLoaded, initialized:
	}

	m.options = options
	m.options.MapEditors = maps.Clone(options.MapEditors)
	if !options.DiscardProgramSpecs {
		m.options.KeepUnmappedProgramSpecs = true
		for _, probe := range m.Probes {
			probe.KeepProgramSpec = true
		}
	}
	m.options.ExcludedFunctions = append(slices.Clone(options.ExcludedFunctions), options.ExcludedEbpfFuncs...)
	for _, rb := range m.RingbufMaps {
		if !slices.Contains(m.RingBuffers, rb) {
			m.RingBuffers = append(m.RingBuffers, rb)
		}
	}
	m.netlinkSocketCache = newNetlinkSocketCache()
	if m.options.DefaultPerfRingBufferSize == 0 {
		m.options.DefaultPerfRingBufferSize = os.Getpagesize()
	}

	// perform a quick sanity check on the provided probes and maps
	if err := m.sanityCheck(); err != nil {
		return err
	}

	if m.options.RLimit != nil {
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, m.options.RLimit); err != nil {
			return fmt.Errorf("could not set memlock limit: %w", err)
		}
	}
	// set resource limit if requested
	if m.options.RemoveRlimit {
		// rlimit.RemoveMemlock automatically detects if rlimit based accounting
		// is used for eBPF maps. Only in this case is the rlimit removed.
		// If cgroup based accounting is in effect, then rlimit is not removed.
		if err := rlimit.RemoveMemlock(); err != nil {
			return fmt.Errorf("couldn't adjust RLIMIT_MEMLOCK: %w", err)
		}
	}

	switch m.state {
	case reset:
		if elf == nil {
			return fmt.Errorf("nil ELF reader")
		}
		if err := m.loadELF(elf); err != nil {
			return err
		}
	case elfLoaded, initialized, stopping, paused, running:
		if elf != nil {
			return ErrManagerELFLoaded
		}
	}

	if m.options.AdditionalExcludedFunctionCollector != nil {
		for key, prog := range m.collectionSpec.Programs {
			if m.options.AdditionalExcludedFunctionCollector.ShouldExcludeFunction(key, prog) {
				m.options.ExcludedFunctions = append(m.options.ExcludedFunctions, key)
			}
		}
		m.options.AdditionalExcludedFunctionCollector.CleanCaches()
	}

	for name, prog := range m.collectionSpec.Programs {
		if slices.Contains(m.options.ExcludedSections, prog.SectionName) {
			m.options.ExcludedFunctions = append(m.options.ExcludedFunctions, name)
		}
	}
	// Remove excluded programs
	for _, excludedFuncName := range m.options.ExcludedFunctions {
		delete(m.collectionSpec.Programs, excludedFuncName)
	}
	for i := 0; i < len(m.Probes); {
		if slices.Contains(m.options.ExcludedFunctions, m.Probes[i].EbpfFuncName) {
			m.Probes = slices.Delete(m.Probes, i, i+1)
		} else {
			i++
		}
	}
	// Remove ConstantEditors that point to only excluded functions
	for i := 0; i < len(m.options.ConstantEditors); {
		ce := m.options.ConstantEditors[i]
		isSpecific := len(ce.ProbeIdentificationPairs) > 0
		// remove excluded ProbeIdentificationPairs
		for j := 0; j < len(ce.ProbeIdentificationPairs); {
			if slices.Contains(m.options.ExcludedFunctions, ce.ProbeIdentificationPairs[j].EbpfFuncName) {
				ce.ProbeIdentificationPairs = slices.Delete(ce.ProbeIdentificationPairs, j, j+1)
			} else {
				j++
			}
		}
		// was a specific constant editor, but all the probes are excluded
		if isSpecific && len(ce.ProbeIdentificationPairs) == 0 {
			m.options.ConstantEditors = slices.Delete(m.options.ConstantEditors, i, i+1)
		} else {
			i++
		}
	}

	// must run before map exclusion in case bypass is disabled
	bypassMap, err := m.setupBypass()
	if err != nil {
		return err
	}

	// Remove excluded maps
	for _, excludeMapName := range m.options.ExcludedMaps {
		delete(m.collectionSpec.Maps, excludeMapName)
	}
	for i := 0; i < len(m.Maps); {
		if slices.Contains(m.options.ExcludedMaps, m.Maps[i].Name) {
			m.Maps = slices.Delete(m.Maps, i, i+1)
		} else {
			i++
		}
	}

	// Match Maps and program specs
	if err = m.matchSpecs(); err != nil {
		return err
	}

	// Configure activated probes
	m.activateProbes()

	// populate bypass indexes on Probe objects
	// this must run after matchSpecs due to CopyProgram handling
	if bypassMap != nil {
		for _, mProbe := range m.Probes {
			if idx, ok := m.bypassIndexes[mProbe.GetEbpfFuncName()]; ok {
				mProbe.bypassIndex = idx
				mProbe.bypassMap = bypassMap
			}
		}
	}

	m.state = initialized
	return nil
}

func (m *Manager) postInit(options Options) error {
	// newEditor program constants
	if len(options.ConstantEditors) > 0 {
		if err := m.editConstants(); err != nil {
			return err
		}
	}

	// newEditor map spec
	if len(options.MapSpecEditors) > 0 {
		if err := m.editMapSpecs(); err != nil {
			return err
		}
	}

	// Setup map routes
	if len(options.InnerOuterMapSpecs) > 0 {
		for _, ioMapSpec := range options.InnerOuterMapSpecs {
			if err := m.editInnerOuterMapSpec(ioMapSpec); err != nil {
				return err
			}
		}
	}

	// Patch instructions
	for _, patcher := range m.InstructionPatchers {
		if err := patcher(m); err != nil {
			return err
		}
	}

	// Load pinned maps and pinned programs to avoid loading them twice
	if err := m.loadPinnedObjects(); err != nil {
		return err
	}

	// Load eBPF program with the provided verifier options
	if err := m.loadCollection(); err != nil {
		if m.collection != nil {
			m.collection.Close()
		}
		return err
	}

	return nil
}

func (m *Manager) setupBypass() (*Map, error) {
	_, hasBypassMapSpec := m.collectionSpec.Maps[bypassMapName]
	if !hasBypassMapSpec {
		return nil, nil
	}
	if !m.options.BypassEnabled {
		m.options.ExcludedMaps = append(m.options.ExcludedMaps, bypassMapName)
		return nil, nil
	}
	// start with 1, so we know if programs even have a valid index set
	m.maxBypassIndex = 1

	const stackOffset = -8
	// place a limit on how far we will inject from the start of a program
	// otherwise we aren't sure what register we need to save/restore, and it could inflate the number of instructions.
	const maxInstructionOffsetFromProgramStart = 1
	// setup bypass constants for all programs
	m.bypassIndexes = make(map[string]uint32, len(m.collectionSpec.Programs))
	for name, p := range m.collectionSpec.Programs {
		for i := 0; i < len(p.Instructions); i++ {
			ins := p.Instructions[i]
			if ins.Reference() != bypassOptInReference {
				continue
			}
			// return error here to ensure we only error on programs that do have a bypass reference
			if i > maxInstructionOffsetFromProgramStart {
				return nil, fmt.Errorf("unable to inject bypass instructions into program %s: bypass reference occurs too late in program", name)
			}
			if i > 0 && p.Instructions[i-1].Src != asm.R1 {
				return nil, fmt.Errorf("unable to inject bypass instructions into program %s: register other than r1 used before injection point", name)
			}

			m.bypassIndexes[name] = m.maxBypassIndex
			newInsns := append([]asm.Instruction{
				asm.Mov.Reg(asm.R6, asm.R1),
				// save bypass index to stack
				asm.StoreImm(asm.RFP, stackOffset, int64(m.maxBypassIndex), asm.Word),
				// store pointer to bypass index
				asm.Mov.Reg(asm.R2, asm.RFP),
				asm.Add.Imm(asm.R2, stackOffset),
				// load map reference
				asm.LoadMapPtr(asm.R1, 0).WithReference(bypassMapName),
				// bpf_map_lookup_elem
				asm.FnMapLookupElem.Call(),
				// if ret == 0, jump to `return 0`
				asm.JEq.Imm(asm.R0, 0, "bypass_return"),
				// pointer indirection of result from map lookup
				asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),
				// if bypass NOT enabled, jump over return
				asm.JEq.Imm(asm.R1, 0, "bypass_continue"),
				asm.Mov.Imm(asm.R0, 0).WithSymbol("bypass_return"),
				asm.Return(),
				// zero out used stack slot
				asm.StoreImm(asm.RFP, stackOffset, 0, asm.Word).WithSymbol("bypass_continue"),
				asm.Mov.Reg(asm.R1, asm.R6),
			}, p.Instructions[i+1:]...)
			// necessary to keep kernel happy about source information for start of program
			newInsns[0] = newInsns[0].WithSource(ins.Source())
			p.Instructions = append(p.Instructions[:i], newInsns...)
			m.maxBypassIndex += 1
			break
		}
	}
	// no programs modified
	if m.maxBypassIndex == 1 {
		m.options.ExcludedMaps = append(m.options.ExcludedMaps, bypassMapName)
		return nil, nil
	}

	hasPerCPU := false
	if err := features.HaveMapType(ebpf.PerCPUArray); err == nil {
		hasPerCPU = true
	}

	bypassMap := &Map{Name: bypassMapName}
	m.Maps = append(m.Maps, bypassMap)

	if m.options.MapSpecEditors == nil {
		m.options.MapSpecEditors = make(map[string]MapSpecEditor)
	}
	m.options.MapSpecEditors[bypassMapName] = MapSpecEditor{
		MaxEntries: m.maxBypassIndex + 1,
		EditorFlag: EditMaxEntries,
	}

	if !hasPerCPU {
		// use scalar value for bypass/enable
		bypassValue = 1
		enableValue = 0
		return bypassMap, nil
	}

	// upgrade map type to per-cpu, if available
	specEditor := m.options.MapSpecEditors[bypassMapName]
	specEditor.Type = ebpf.PerCPUArray
	specEditor.EditorFlag |= EditType
	m.options.MapSpecEditors[bypassMapName] = specEditor

	// allocate per-cpu slices used for bypass/enable
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, err
	}
	if bypassValue == nil {
		bypassValue = makeAndSet(cpus, uint32(1))
	}
	if enableValue == nil {
		enableValue = makeAndSet(cpus, uint32(0))
	}

	return bypassMap, nil
}

// releaseKernelBTF drops the references to the kernel BTF that are only needed while loading programs, so a long-lived
// manager does not pin the parsed kernel BTF (vmlinux) for the whole process lifetime. Both the KernelTypes spec passed
// to the verifier and the shared BTF cache are cleared, symmetrically. This is a no-op when KeepKernelBTF is set (for
// example when the caller relies on CloneProgram, which reloads programs and needs KernelTypes for CO-RE relocations).
func (m *Manager) releaseKernelBTF() {
	if m.options.KeepKernelBTF {
		return
	}
	m.options.VerifierOptions.Programs.KernelTypes = nil
	m.options.VerifierOptions.Cache = nil
}

// Start - Attach eBPF programs, start perf ring readers and apply maps and tail calls routing.
func (m *Manager) Start() error {
	m.stateLock.Lock()
	switch m.state {
	case reset, elfLoaded, stopping:
		m.stateLock.Unlock()
		return ErrManagerNotInitialized
	case running:
		m.stateLock.Unlock()
		return nil
	case initialized, paused:
	}

	// release kernel BTF: it is only needed while loading programs and should no longer be needed now
	m.releaseKernelBTF()

	// clean up tracefs
	if err := m.cleanupTraceFS(); err != nil {
		m.stateLock.Unlock()
		return fmt.Errorf("failed to cleanup tracefs: %w", err)
	}

	// Start perf ring readers
	for _, perfRing := range m.PerfMaps {
		if m.options.SkipPerfMapReaderStartup[perfRing.Name] {
			continue
		}
		if err := perfRing.Start(); err != nil {
			// Clean up
			_ = m.stop(CleanInternal)
			m.stateLock.Unlock()
			return err
		}
	}

	// Start ring buffer readers
	for _, ringBuffer := range m.RingBuffers {
		if m.options.SkipRingbufferReaderStartup[ringBuffer.Name] {
			continue
		}
		if err := ringBuffer.Start(); err != nil {
			// Clean up
			_ = m.stop(CleanInternal)
			m.stateLock.Unlock()
			return err
		}
	}

	// Attach eBPF programs
	for _, probe := range m.Probes {
		// ignore the error, they are already collected per probes and will be surfaced by the
		// activation validators if needed.
		_ = probe.Attach()
	}

	m.state = running
	m.stateLock.Unlock()

	// Check probe selectors
	var validationErrs error
	for _, selector := range m.options.ActivatedProbes {
		if err := selector.RunValidator(m); err != nil {
			validationErrs = errors.Join(validationErrs, err)
		}
	}
	if validationErrs != nil {
		// Clean up
		_ = m.Stop(CleanInternal)
		return fmt.Errorf("probes activation validation failed: %w", validationErrs)
	}

	// Handle Maps router
	if err := m.UpdateMapRoutes(m.options.MapRouter...); err != nil {
		// Clean up
		_ = m.Stop(CleanInternal)
		return err
	}

	// Handle Program router
	if err := m.UpdateTailCallRoutes(m.options.TailCallRouter...); err != nil {
		// Clean up
		_ = m.Stop(CleanInternal)
		return err
	}
	return nil
}

func (m *Manager) Pause() error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	switch m.state {
	case paused:
		return nil
	case reset, elfLoaded, initialized, stopping:
		return ErrManagerNotStarted
	case running:
	}
	if !m.options.BypassEnabled {
		return nil
	}

	for _, probe := range m.Probes {
		if err := probe.Pause(); err != nil {
			return err
		}
	}
	m.state = paused
	return nil
}

func (m *Manager) Resume() error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	switch m.state {
	case running:
		return nil
	case reset, elfLoaded, initialized, stopping:
		return ErrManagerNotStarted
	case paused:
	}
	if !m.options.BypassEnabled {
		return nil
	}

	for _, probe := range m.Probes {
		if err := probe.Resume(); err != nil {
			return err
		}
	}
	m.state = running
	return nil
}

// Stop - Detach all eBPF programs and stop perf ring readers. The cleanup parameter defines which maps should be closed.
// See MapCleanupType for mode.
func (m *Manager) Stop(cleanup MapCleanupType) error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	switch m.state {
	case reset, elfLoaded:
		return ErrManagerNotInitialized
	case initialized, stopping, paused, running:
		// stopping is only visible while another stopReaders holds the unlock
		// window. After StopReaders returns, previousState is restored, so a
		// later Stop() sees initialized/paused/running. Accepting stopping here
		// covers the concurrent Stop() that arrives during that window.
		return m.stop(cleanup)
	}
	return nil
}

// StopReaders - Stop the kernel events readers Perf or Ring buffer.
func (m *Manager) StopReaders(cleanup MapCleanupType) error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	return m.stopReaders(cleanup)
}

// stopReaders - Thread unsafe version of StopReaders. The caller must hold stateLock.
func (m *Manager) stopReaders(cleanup MapCleanupType) error {
	// Block Start/NewPerfRing/NewRingBuffer for the unlock window below, then
	// restore so StopReaders is not a sticky state. Only restore if we are
	// still stopping: a concurrent Stop() may already have gone to reset.
	previousState := m.state
	m.state = stopping
	var errs []error

	// Stop perf ring readers
	for _, perfRing := range m.PerfMaps {
		if closeErr := perfRing.closeReader(); closeErr != nil {
			errs = append(errs, fmt.Errorf("perf ring reader %s couldn't gracefully shut down: %w", perfRing.Name, closeErr))
		}
	}

	// Stop ring buffer readers
	for _, ringBuffer := range m.RingBuffers {
		if closeErr := ringBuffer.closeReader(); closeErr != nil {
			errs = append(errs, fmt.Errorf("ring buffer reader %s couldn't gracefully shut down: %w", ringBuffer.Name, closeErr))
		}
	}

	// Temporarily release manager.stateLock to avoid a deadlock:
	// reader goroutine handlers may call Manager methods that need
	// stateLock.RLock(). By releasing the write lock, handlers can
	// complete, allowing goroutines to loop back to ReadInto which
	// will return ErrClosed.
	m.stateLock.Unlock()

	for _, perfRing := range m.PerfMaps {
		perfRing.wgReader.Wait()
	}
	for _, ringBuffer := range m.RingBuffers {
		ringBuffer.wgReader.Wait()
	}

	// Now get the lock again
	m.stateLock.Lock()

	// Clean up underlying maps
	for _, perfRing := range m.PerfMaps {
		if closeErr := perfRing.cleanupMap(cleanup); closeErr != nil {
			errs = append(errs, fmt.Errorf("perf ring reader %s couldn't close map: %w", perfRing.Name, closeErr))
		}
	}
	for _, ringBuffer := range m.RingBuffers {
		if closeErr := ringBuffer.cleanupMap(cleanup); closeErr != nil {
			errs = append(errs, fmt.Errorf("ring buffer reader %s couldn't close map: %w", ringBuffer.Name, closeErr))
		}
	}

	if m.state == stopping {
		m.state = previousState
	}
	return errors.Join(errs...)
}

func (m *Manager) stopProbes() error {
	// Calling close() on perf_kprobe PMUs takes 30-50ms, which adds up for large projects.
	// Close them concurrently to speed things up
	var eg errgroup.Group
	eg.SetLimit(12)
	for _, probe := range m.Probes {
		eg.Go(func() error {
			if stopErr := probe.Stop(); stopErr != nil {
				return fmt.Errorf("program %s couldn't gracefully shut down: %w", probe.GetIdentificationPair(), stopErr)
			}
			return nil
		})
	}
	return eg.Wait()
}

// stop - Thread unsafe version of Stop. Requires the manager lock to not panic
func (m *Manager) stop(cleanup MapCleanupType) error {
	var errs []error
	errs = append(errs, m.stopReaders(cleanup))

	// check again state since stopReaders released the lock temporary
	switch m.state {
	case reset, elfLoaded:
		return ErrManagerNotInitialized
	case initialized, stopping, paused, running:
	}

	// Detach eBPF programs
	errs = append(errs, m.stopProbes())

	// Close maps
	for _, managerMap := range m.Maps {
		if closeErr := managerMap.Close(cleanup); closeErr != nil {
			errs = append(errs, fmt.Errorf("couldn't gracefully close map %s: %w", managerMap.Name, closeErr))
		}
	}

	// Close all netlink sockets
	m.netlinkSocketCache.cleanup()

	// Clean up collection
	// Note: we might end up closing the same programs or maps multiple times but the library gracefully handles those
	// situations. We can't rely only on the collection to close all maps and programs because some pinned objects were
	// removed from the collection.
	m.collection.Close()
	m.state = reset
	return errors.Join(errs...)

}

// NewMap - Create a new map using the provided parameters. The map is added to the list of maps managed by the manager.
// Use a MapRoute to make this map available to the programs of the manager.
func (m *Manager) NewMapFromSpec(spec *ebpf.MapSpec, options MapOptions) (*ebpf.Map, error) {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	switch m.state {
	case reset, elfLoaded:
		return nil, ErrManagerNotInitialized
	case initialized, stopping, paused, running:
	}
	if m.collection == nil {
		return nil, ErrManagerNotInitialized
	}

	// check if the name of the new map is available
	_, exists, _ := m.getMap(spec.Name)
	if exists {
		return nil, ErrMapNameInUse
	}

	// Create the new map
	managerMap, err := loadNewMap(spec, options)
	if err != nil {
		return nil, err
	}

	// init map
	if err := managerMap.init(); err != nil {
		// Clean up
		_ = managerMap.Close(CleanInternal)
		return nil, err
	}

	// Add map to the list of maps managed by the manager
	m.Maps = append(m.Maps, managerMap)
	return managerMap.array, nil
}

// CloneMap - Duplicates the spec of an existing map, before creating a new one.
// Use a MapRoute to make this map available to the programs of the manager.
func (m *Manager) CloneMap(name string, newName string, options MapOptions) (*ebpf.Map, error) {
	// Select map to clone
	oldSpec, exists, err := m.GetMapSpec(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("failed to clone maps/%s: %w", name, ErrUnknownSection)
	}

	// Duplicate spec and create a new map
	spec := oldSpec.Copy()
	spec.Name = newName
	return m.NewMapFromSpec(spec, options)
}

// AddHook - Hook an existing program to a hook point. This is particularly useful when you need to trigger an
// existing program on a hook point that is determined at runtime. For example, you might want to hook an existing
// eBPF TC classifier to the newly created interface of a container. Make sure to specify a unique uid in the new probe,
// you will need it if you want to detach the program later. The original program is selected using the provided UID,
// the section and the eBPF function name provided in the new probe.
func (m *Manager) AddHook(UID string, newProbe *Probe) error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	switch m.state {
	case reset, elfLoaded:
		return ErrManagerNotInitialized
	case initialized, stopping, paused, running:
	}
	if m.collection == nil {
		return ErrManagerNotInitialized
	}

	oldID := ProbeIdentificationPair{UID: UID, EbpfFuncName: newProbe.EbpfFuncName}
	// Look for the eBPF program
	progs, found, err := m.getProgram(oldID)
	if err != nil {
		return err
	}
	if !found || len(progs) == 0 {
		return fmt.Errorf("couldn't find program %s: %w", oldID, ErrUnknownSectionOrFuncName)
	}
	prog := progs[0]
	progSpecs, found, _ := m.getProgramSpec(oldID)
	if !found || len(progSpecs) == 0 {
		return fmt.Errorf("couldn't find programSpec %s: %w", oldID, ErrUnknownSectionOrFuncName)
	}
	progSpec := progSpecs[0]

	// Ensure that the new probe is enabled
	newProbe.Enabled = true

	// Make sure the provided identification pair is unique
	_, exists, _ := m.getProgramSpec(newProbe.GetIdentificationPair())
	if exists {
		return fmt.Errorf("probe %s already exists: %w", newProbe.GetIdentificationPair(), ErrIdentificationPairInUse)
	}

	// Clone program
	clonedProg, err := prog.Clone()
	if err != nil {
		return fmt.Errorf("couldn't clone %v: %w", oldID, err)
	}
	newProbe.program = clonedProg
	newProbe.programSpec = progSpec

	var bypassMap *Map
	for _, mp := range m.Maps {
		if mp.Name == bypassMapName {
			bypassMap = mp
			break
		}
	}
	bypassIndex, ok := m.bypassIndexes[newProbe.EbpfFuncName]
	if ok && bypassMap != nil {
		newProbe.bypassIndex = bypassIndex
		newProbe.bypassMap = bypassMap
	}

	// init program
	if err = newProbe.init(m); err != nil {
		// clean up
		_ = newProbe.Stop()
		return fmt.Errorf("failed to initialize new probe: %w", err)
	}

	// Pin if needed
	if newProbe.PinPath != "" {
		if err = newProbe.program.Pin(newProbe.PinPath); err != nil {
			// clean up
			_ = newProbe.Stop()
			return fmt.Errorf("couldn't pin new probe: %w", err)
		}
	}

	// Attach program
	if err = newProbe.Attach(); err != nil {
		// clean up
		_ = newProbe.Stop()
		return fmt.Errorf("couldn't attach new probe: %w", err)
	}

	// Add probe to the list of probes
	m.Probes = append(m.Probes, newProbe)
	return nil
}

// DetachHook - Detach an eBPF program from a hook point. If there is only one instance left of this program in the
// kernel, then the probe will be detached but the program will not be closed (so that it can be used later). In that
// case, calling DetachHook has essentially the same effect as calling Detach() on the right Probe instance. However,
// if there are more than one instance in the kernel of the requested program, then the probe selected by the provided
// ProbeIdentificationPair is detached, and its own handle of the program is closed.
func (m *Manager) DetachHookByID(id ProbeIdentificationPair) error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	switch m.state {
	case reset, elfLoaded:
		return ErrManagerNotInitialized
	case initialized, stopping, paused, running:
	}
	if m.collection == nil {
		return ErrManagerNotInitialized
	}

	// Check how many instances of the program are left in the kernel
	progs, _, err := m.getProgram(ProbeIdentificationPair{UID: "", EbpfFuncName: id.EbpfFuncName})
	if err != nil {
		return err
	}
	shouldStop := len(progs) > 1

	// Look for the probe
	idToDelete := -1
	for mID, mProbe := range m.Probes {
		if mProbe.GetIdentificationPair() == id {
			// Detach or stop the probe depending on shouldStop
			if shouldStop {
				if err = mProbe.Stop(); err != nil {
					return fmt.Errorf("couldn't stop probe %s: %w", id, err)
				}
			} else {
				if err = mProbe.Detach(); err != nil {
					return fmt.Errorf("couldn't detach probe %s: %w", id, err)
				}
			}
			idToDelete = mID
		}
	}
	if idToDelete >= 0 {
		m.Probes = slices.Delete(m.Probes, idToDelete, idToDelete+1)
	}
	return nil
}

// CloneProgram - Create a clone of a program, load it in the kernel and attach it to its hook point. Since the eBPF
// program instructions are copied before the program is loaded, you can edit them with a ConstantEditor, or remap
// the eBPF maps as you like. This is particularly useful to work around the absence of Array of Maps and Hash of Maps:
// first create the new maps you need, then clone the program you're interested in and rewrite it with the new maps,
// using a MapEditor. The original program is selected using the provided UID and the section provided in the new probe.
// Note that the BTF based constant edition will not work with this method.
func (m *Manager) CloneProgram(UID string, newProbe *Probe, constantsEditors []ConstantEditor, mapEditors map[string]*ebpf.Map) error {
	return m.CloneProgramWithSpecEditor(UID, newProbe, constantsEditors, mapEditors, nil)
}

// CloneProgramWithSpecEditor - does the same thing as CloneProgram, but allows to intercept the new program spec before the probe
// is initialized. This is useful for example to clone an fentry probe, and edit the AttachTo field before the init of the new probe.
func (m *Manager) CloneProgramWithSpecEditor(UID string, newProbe *Probe, constantsEditors []ConstantEditor, mapEditors map[string]*ebpf.Map, specEditor func(spec *ebpf.ProgramSpec)) error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	switch m.state {
	case reset, elfLoaded:
		return ErrManagerNotInitialized
	case initialized, stopping, paused, running:
	}
	if m.collection == nil {
		return ErrManagerNotInitialized
	}

	oldID := ProbeIdentificationPair{UID: UID, EbpfFuncName: newProbe.EbpfFuncName}
	var oldProgramSpec *ebpf.ProgramSpec
	// look for an existing probe
	oldProbe, found := m.getProbe(oldID)
	if found {
		// check if the program spec of this probe was removed
		if !oldProbe.KeepProgramSpec {
			return fmt.Errorf("couldn't clone %s: this probe was cleaned up because KeepProgramSpec was disabled", oldID)
		}
		oldProgramSpec = oldProbe.programSpec
	} else {
		// the cloned program might not have a dedicated Probe, fallback to a collectionPec lookup
		progSpecs, found, err := m.getProgramSpec(oldID)
		if err != nil {
			return err
		}
		if !found || len(progSpecs) == 0 {
			return fmt.Errorf("couldn't find programSpec %v: %w", oldID, ErrUnknownSectionOrFuncName)
		}
		oldProgramSpec = progSpecs[0]

		// the program spec was found
		if !m.options.KeepUnmappedProgramSpecs {
			return fmt.Errorf("couldn't clone %s: this probe was cleaned up because KeepUnmappedProgramSpecs was disabled", oldID)
		}
	}

	// Check if the new probe has a unique identification pair
	_, exists, _ := m.getProgram(newProbe.GetIdentificationPair())
	if exists {
		return fmt.Errorf("couldn't add probe %v: %w", newProbe.GetIdentificationPair(), ErrIdentificationPairInUse)
	}

	// Make sure the new probe is activated
	newProbe.Enabled = true

	// Clone the program
	clonedSpec := oldProgramSpec.Copy()
	if specEditor != nil {
		specEditor(clonedSpec)
	}
	newProbe.programSpec = clonedSpec

	// newEditor constants
	for _, editor := range constantsEditors {
		if err := m.editConstant(newProbe.programSpec, editor); err != nil {
			return fmt.Errorf("couldn't edit constant %s: %w", editor.Name, err)
		}
	}

	// Write current maps
	if err := m.rewriteMaps(newProbe.programSpec, m.collection.Maps, false); err != nil {
		return fmt.Errorf("couldn't rewrite maps in %v: %w", newProbe.GetIdentificationPair(), err)
	}

	// Rewrite with new maps
	if err := m.rewriteMaps(newProbe.programSpec, mapEditors, true); err != nil {
		return fmt.Errorf("couldn't rewrite maps in %v: %w", newProbe.GetIdentificationPair(), err)
	}

	// init
	if err := newProbe.initWithOptions(m, true, true); err != nil {
		// clean up
		_ = newProbe.Stop()
		return fmt.Errorf("failed to initialize new probe %v: %w", newProbe.GetIdentificationPair(), err)
	}

	// Attach new program
	if err := newProbe.Attach(); err != nil {
		// clean up
		_ = newProbe.Stop()
		return fmt.Errorf("failed to attach new probe %v: %w", newProbe.GetIdentificationPair(), err)
	}

	// Add probe to the list of probes
	m.Probes = append(m.Probes, newProbe)
	return nil
}

func (m *Manager) getProbeProgramSpec(funcName string) (*ebpf.ProgramSpec, error) {
	spec, ok := m.collectionSpec.Programs[funcName]
	if !ok {
		return nil, fmt.Errorf("couldn't find program spec for func %s: %w", funcName, ErrUnknownSectionOrFuncName)
	}
	return spec, nil
}

func (m *Manager) getProbeProgram(funcName string) (*ebpf.Program, error) {
	p, ok := m.collection.Programs[funcName]
	if !ok {
		return nil, fmt.Errorf("couldn't find program %s: %w", funcName, ErrUnknownSectionOrFuncName)
	}
	return p, nil
}

// matchSpecs - Match loaded maps and program specs with the maps and programs provided to the manager
func (m *Manager) matchSpecs() error {
	// Match programs
	for _, probe := range m.Probes {
		programSpec, err := m.getProbeProgramSpec(probe.EbpfFuncName)
		if err != nil {
			return err
		}
		if !probe.CopyProgram {
			probe.programSpec = programSpec
		} else {
			probe.programSpec = programSpec.Copy()
			m.collectionSpec.Programs[probe.GetEbpfFuncName()] = probe.programSpec
		}
	}

	// Match maps
	for _, managerMap := range m.Maps {
		spec, ok := m.collectionSpec.Maps[managerMap.Name]
		if !ok {
			return fmt.Errorf("couldn't find map at maps/%s: %w", managerMap.Name, ErrUnknownSection)
		}
		spec.Contents = managerMap.Contents
		managerMap.arraySpec = spec
	}

	// Match perfmaps
	for _, perfMap := range m.PerfMaps {
		spec, ok := m.collectionSpec.Maps[perfMap.Name]
		if !ok {
			return fmt.Errorf("couldn't find map at maps/%s: %w", perfMap.Name, ErrUnknownSection)
		}
		perfMap.arraySpec = spec
	}

	// Match ring buffer
	for _, ringBuffer := range m.RingBuffers {
		spec, ok := m.collectionSpec.Maps[ringBuffer.Name]
		if !ok {
			return fmt.Errorf("couldn't find map at maps/%s: %w", ringBuffer.Name, ErrUnknownSection)
		}
		ringBuffer.arraySpec = spec
	}

	return nil
}

// matchBPFObjects - Match loaded maps and program specs with the maps and programs provided to the manager
func (m *Manager) matchBPFObjects() error {
	// Match programs
	var mappedProgramSpecNames []string
	for _, probe := range m.Probes {
		if probe.program == nil {
			program, err := m.getProbeProgram(probe.GetEbpfFuncName())
			if err != nil {
				return err
			}
			probe.program = program
			probe.checkPin = true
		} else {
			// A program reopened from bpffs was excluded from the load spec.
			m.collection.Programs[probe.GetEbpfFuncName()] = probe.program
		}
		mappedProgramSpecNames = append(mappedProgramSpecNames, probe.EbpfFuncName)
	}

	// cleanup unmapped ProgramSpec now
	if !m.options.KeepUnmappedProgramSpecs {
	collectionSpec:
		for specName, spec := range m.collectionSpec.Programs {
			for _, name := range mappedProgramSpecNames {
				if specName == name {
					continue collectionSpec
				}
			}
			cleanupProgramSpec(spec)
		}
	}

	// Match maps
	for _, managerMap := range m.Maps {
		arr, ok := m.collection.Maps[managerMap.Name]
		if !ok {
			return fmt.Errorf("couldn't find map at maps/%s: %w", managerMap.Name, ErrUnknownSection)
		}
		// the `*ebpf.Map` reference may already be populated if pinned
		if managerMap.array != nil {
			// we don't need multiple references, so `Close` the new one
			_ = arr.Close()
			m.collection.Maps[managerMap.Name] = managerMap.array
			continue
		}
		managerMap.array = arr
	}

	// Match perfmaps
	for _, perfMap := range m.PerfMaps {
		arr, ok := m.collection.Maps[perfMap.Name]
		if !ok {
			return fmt.Errorf("couldn't find map at maps/%s: %w", perfMap.Name, ErrUnknownSection)
		}
		// the `*ebpf.Map` reference may already be populated if pinned
		if perfMap.array != nil {
			// we don't need multiple references, so `Close` the new one
			_ = arr.Close()
			m.collection.Maps[perfMap.Name] = perfMap.array
			continue
		}
		perfMap.array = arr
	}

	// Match ring buffers
	for _, ringBuffer := range m.RingBuffers {
		arr, ok := m.collection.Maps[ringBuffer.Name]
		if !ok {
			return fmt.Errorf("couldn't find map at maps/%s: %w", ringBuffer.Name, ErrUnknownSection)
		}
		// the `*ebpf.Map` reference may already be populated if pinned
		if ringBuffer.array != nil {
			// we don't need multiple references, so `Close` the new one
			_ = arr.Close()
			m.collection.Maps[ringBuffer.Name] = ringBuffer.array
			continue
		}
		ringBuffer.array = arr
	}

	return nil
}

func (m *Manager) activateProbes() {
	shouldPopulateActivatedProbes := len(m.options.ActivatedProbes) == 0
	for _, mProbe := range m.Probes {
		shouldActivate := shouldPopulateActivatedProbes
		for _, selector := range m.options.ActivatedProbes {
			for _, p := range selector.GetProbesIdentificationPairList() {
				if mProbe.GetIdentificationPair() == p {
					shouldActivate = true
				}
			}
		}
		mProbe.Enabled = shouldActivate

		if shouldPopulateActivatedProbes {
			// this will ensure that we check that everything has been activated by default when no selectors are provided
			m.options.ActivatedProbes = append(m.options.ActivatedProbes, &ProbeSelector{
				ProbeIdentificationPair: mProbe.GetIdentificationPair(),
			})
		}
	}
}

// UpdateActivatedProbes - update the list of activated probes
func (m *Manager) UpdateActivatedProbes(selectors []ProbesSelector) error {
	m.stateLock.Lock()
	switch m.state {
	case reset, elfLoaded:
		m.stateLock.Unlock()
		return ErrManagerNotInitialized
	case initialized, stopping, paused, running:
	}

	currentProbes := make(map[ProbeIdentificationPair]*Probe)
	for _, p := range m.Probes {
		pip := ProbeIdentificationPair{UID: p.UID, EbpfFuncName: p.EbpfFuncName}
		if p.Enabled {
			currentProbes[pip] = p
		}
	}

	nextProbes := make(map[ProbeIdentificationPair]bool)
	for _, selector := range selectors {
		for _, id := range selector.GetProbesIdentificationPairList() {
			if !slices.Contains(m.options.ExcludedFunctions, id.EbpfFuncName) {
				pip := ProbeIdentificationPair{UID: id.UID, EbpfFuncName: id.EbpfFuncName}
				nextProbes[pip] = true
			}
		}
	}

	for id := range nextProbes {
		var probe *Probe
		if currentProbe, alreadyPresent := currentProbes[id]; alreadyPresent {
			delete(currentProbes, id)
			probe = currentProbe
		} else {
			var found bool
			probe, found = m.getProbe(id)
			if !found {
				m.stateLock.Unlock()
				return fmt.Errorf("couldn't find program %s: %w", id, ErrUnknownSectionOrFuncName)
			}
			probe.Enabled = true
		}
		if !probe.IsRunning() {
			// ignore all errors, they are already collected per probe and will be surfaced by the
			// activation validators if needed.
			_ = probe.init(m)
			_ = probe.Attach()
		}
	}

	for _, probe := range currentProbes {
		if err := probe.Detach(); err != nil {
			m.stateLock.Unlock()
			return err
		}
		probe.Enabled = false
	}

	// update activated probes & check activation
	m.options.ActivatedProbes = selectors

	m.stateLock.Unlock()

	var validationErrs error
	for _, selector := range selectors {
		if err := selector.RunValidator(m); err != nil {
			validationErrs = errors.Join(validationErrs, err)
		}
	}

	if validationErrs != nil {
		// Clean up
		_ = m.Stop(CleanInternal)
		return fmt.Errorf("probes activation validation failed: %w", validationErrs)
	}

	return nil
}

// rewriteMaps - Rewrite the provided program spec with the provided maps. failOnError controls if an error should be
// returned when a map couldn't be rewritten.
func (m *Manager) rewriteMaps(program *ebpf.ProgramSpec, eBPFMaps map[string]*ebpf.Map, failOnError bool) error {
	for symbol, eBPFMap := range eBPFMaps {
		err := program.Instructions.AssociateMap(symbol, eBPFMap)
		if err != nil && failOnError {
			return fmt.Errorf("couldn't rewrite map %s: %w", symbol, err)
		}
	}
	return nil
}

// loadCollection - Load the eBPF maps and programs in the CollectionSpec. Programs and Maps are pinned when requested.
func (m *Manager) loadCollection() error {
	var err error

	opts := m.options.VerifierOptions
	// map references replaced this way will get a cloned reference to the *ebpf.Map upon collection load
	opts.MapReplacements = maps.Clone(opts.MapReplacements)
	if opts.MapReplacements == nil {
		opts.MapReplacements = make(map[string]*ebpf.Map)
	}
	maps.Copy(opts.MapReplacements, m.options.MapEditors)
	for name := range opts.MapReplacements {
		if _, ok := m.collectionSpec.Maps[name]; !ok && m.options.MapEditorsIgnoreMissingMaps {
			// prevent error for missing map by removing the editor
			delete(opts.MapReplacements, name)
		}
	}

	m.collection, err = ebpf.NewCollectionWithOptions(m.collectionSpec, opts)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// include error twice to preserve context, and still allow unwrapping if desired
			return fmt.Errorf("verifier error loading eBPF programs: %w\n%+v", err, ve)
		}
		return fmt.Errorf("couldn't load eBPF programs: %w", err)
	}

	// match loaded bpf objects
	if err = m.matchBPFObjects(); err != nil {
		return fmt.Errorf("couldn't match bpf objects: %w", err)
	}

	// Initialize Maps
	for _, managerMap := range m.Maps {
		if err := managerMap.init(); err != nil {
			return err
		}
	}

	// Initialize PerfMaps
	for _, perfMap := range m.PerfMaps {
		if err := perfMap.init(m); err != nil {
			return err
		}
	}

	// Initialize ring buffers
	for _, ringBuffer := range m.RingBuffers {
		if err := ringBuffer.init(m); err != nil {
			return err
		}
	}

	// Initialize Probes
	for _, probe := range m.Probes {
		// Find program
		if err := probe.init(m); err != nil {
			return err
		}
	}
	return nil
}

// loadPinnedObjects - Loads pinned programs and maps from the bpf virtual file system. If a map is found, the
// CollectionSpec will be edited so that references to that map point to the pinned one. If a program is found, it will
// be detached from the CollectionSpec to avoid loading it twice.
func (m *Manager) loadPinnedObjects() error {
	// Look for pinned maps
	for _, managerMap := range m.Maps {
		if managerMap.PinPath == "" {
			continue
		}
		if err := m.loadPinnedMap(managerMap); err != nil {
			if errors.Is(err, ErrPinnedObjectNotFound) {
				continue
			}
			return err
		}
	}

	// Look for pinned perf buffer
	for _, perfMap := range m.PerfMaps {
		if perfMap.PinPath == "" {
			continue
		}
		if err := m.loadPinnedMap(&perfMap.Map); err != nil {
			if errors.Is(err, ErrPinnedObjectNotFound) {
				continue
			}
			return err
		}
	}

	// Look for pinned perf buffer
	for _, ringBuffer := range m.RingBuffers {
		if ringBuffer.PinPath == "" {
			continue
		}
		if err := m.loadPinnedMap(&ringBuffer.Map); err != nil {
			if errors.Is(err, ErrPinnedObjectNotFound) {
				continue
			}
			return err
		}
	}

	// Look for pinned programs
	for _, prog := range m.Probes {
		if prog.PinPath == "" {
			continue
		}
		if err := m.loadPinnedProgram(prog); err != nil {
			if errors.Is(err, ErrPinnedObjectNotFound) {
				continue
			}
			return err
		}
	}
	return nil
}

// loadPinnedMap - Loads a pinned map
func (m *Manager) loadPinnedMap(managerMap *Map) error {
	// Check if the pinned object exists
	if _, err := os.Stat(managerMap.PinPath); err != nil {
		return ErrPinnedObjectNotFound
	}

	pinnedMap, err := ebpf.LoadPinnedMap(managerMap.PinPath, nil)
	if err != nil {
		return fmt.Errorf("couldn't load map %s from %s: %w", managerMap.Name, managerMap.PinPath, err)
	}

	if m.options.MapEditors == nil {
		m.options.MapEditors = make(map[string]*ebpf.Map)
	}
	m.options.MapEditors[managerMap.Name] = pinnedMap
	managerMap.array = pinnedMap
	return nil
}

// loadPinnedProgram - Loads a pinned program
func (m *Manager) loadPinnedProgram(prog *Probe) error {
	// Check if the pinned object exists
	if _, err := os.Stat(prog.PinPath); err != nil {
		return ErrPinnedObjectNotFound
	}

	pinnedProg, err := ebpf.LoadPinnedProgram(prog.PinPath, nil)
	if err != nil {
		return fmt.Errorf("couldn't load program %v from %s: %w", prog.GetIdentificationPair(), prog.PinPath, err)
	}
	prog.program = pinnedProg

	// Detach program from CollectionSpec
	delete(m.collectionSpec.Programs, prog.GetEbpfFuncName())
	return nil
}

// sanityCheck - Checks that the probes and maps of the manager were properly defined
func (m *Manager) sanityCheck() error {
	// Check if map names are unique
	cache := map[string]bool{}
	for _, managerMap := range m.Maps {
		_, ok := cache[managerMap.Name]
		if ok {
			return fmt.Errorf("map %s failed the sanity check: %w", managerMap.Name, ErrMapNameInUse)
		}
		cache[managerMap.Name] = true
	}

	for _, perfMap := range m.PerfMaps {
		_, ok := cache[perfMap.Name]
		if ok {
			return fmt.Errorf("map %s failed the sanity check: %w", perfMap.Name, ErrMapNameInUse)
		}
		cache[perfMap.Name] = true
	}

	for _, ringBuffer := range m.RingBuffers {
		_, ok := cache[ringBuffer.Name]
		if ok {
			return fmt.Errorf("map %s failed the sanity check: %w", ringBuffer.Name, ErrMapNameInUse)
		}
		cache[ringBuffer.Name] = true
	}

	// Check if probes identification pairs are unique, request the usage of CloneProbe otherwise
	cache = map[string]bool{}
	for _, managerProbe := range m.Probes {
		key := managerProbe.GetIdentificationPair().String() //nolint:staticcheck
		_, ok := cache[key]
		if ok {
			return fmt.Errorf("%s failed the sanity check: %w", key, ErrCloneProbeRequired)
		}
		cache[key] = true
	}
	return nil
}
