package manager

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/gojue/ebpfmanager/internal"
)

type AttachMethod uint32

const (
	AttachMethodNotSet AttachMethod = iota
	AttachWithPerfEventOpen
	AttachWithProbeEvents
)

const bypassMapName = "program_bypassed"
const bypassOptInReference = "bypass_program"

// values used for map update to bypass/enable programs
var bypassValue any
var enableValue any

// Probe - Main eBPF probe wrapper. This structure is used to store the required data to attach a loaded eBPF
// program to its hook point.
type Probe struct {
	netlinkSocketCache      *netlinkSocketCache
	program                 *ebpf.Program
	programSpec             *ebpf.ProgramSpec
	state                   state
	stateLock               sync.RWMutex
	manualLoadNeeded        bool
	checkPin                bool
	attachPID               int
	attachRetryAttempt      uint
	kprobeHookPointNotExist bool
	systemWideID            int
	programTag              string
	kprobeType              probeType
	isReturnProbe           bool
	link                    netlink.Link
	tcFilter                netlink.BpfFilter
	tcClsActQdisc           netlink.Qdisc
	progLink                io.Closer
	bypassIndex             uint32
	bypassMap               *Map

	// lastError - stores the last error that the probe encountered, it is used to surface a more useful error message
	// when one of the validators (see Options.ActivatedProbes) fails.
	lastError error

	// ProbeIdentificationPair is used to identify the current probe
	UID          string
	EbpfFuncName string

	// Section and AttachToFuncName retain the fork's probe configuration API.
	// Section overrides the ELF section used to select the attachment type.
	Section          string
	AttachToFuncName string
	// UAddress is a file offset supplied by the caller. UprobeOffset is relative
	// to UAddress, or to the resolved symbol when UAddress is zero.
	UAddress         uint64
	AttachPID        int
	LinkPinPath      string
	Ifindex          int32
	Ifname           string
	IfindexNetns     uint64
	SkipLoopback     bool
	uprobeFileOffset uint64

	// CopyProgram - When enabled, this option will make a unique copy of the program section for the current program
	CopyProgram bool

	// KeepProgramSpec - Defines if the internal *ProgramSpec should be cleaned up after the probe has been successfully
	// attached to free up memory. If you intend to make a copy of this Probe later, you should explicitly set this
	// option to true.
	KeepProgramSpec bool

	// SyscallFuncName - Name of the syscall on which the program should be hooked. As the exact kernel symbol may
	// differ from one kernel version to the other, the right prefix will be computed automatically at runtime.
	// If a syscall name is not provided, the section name (without its probe type prefix) is assumed to be the
	// hook point.
	SyscallFuncName string

	// MatchFuncName - Pattern used to find the function(s) to attach to
	// FOR KPROBES: When this field is used, the provided pattern is matched against the list of available symbols
	// in /sys/kernel/debug/tracing/available_filter_functions. If the exact function does not exist, then the first
	// symbol matching the provided pattern will be used. This option requires debugfs.
	//
	// FOR UPROBES: When this field is used, the provided pattern is matched against the list of symbols in the symbol
	// table of the provided elf binary. If the exact function does not exist, then the first symbol matching the
	// provided pattern will be used.
	MatchFuncName string

	// HookFuncName - Exact name of the symbol to hook onto. When this field is set, MatchFuncName and SyscallFuncName
	// are ignored.
	HookFuncName string

	// TracepointCategory - (Tracepoint) The manager expects the tracepoint category to be parsed from the eBPF section
	// in which the eBPF function of this Probe lives (SEC("tracepoint/[category]/[name]")). However, you can use this
	// field to override it.
	TracepointCategory string

	// TracepointName - (Tracepoint) The manager expects the tracepoint name to be parsed from the eBPF section
	// in which the eBPF function of this Probe lives (SEC("tracepoint/[category]/[name]")). However, you can use this
	// field to override it.
	TracepointName string

	// Enabled - Indicates if a probe should be enabled or not. This parameter can be set at runtime using the
	// Manager options (see ActivatedProbes)
	Enabled bool

	// PinPath - Once loaded, the eBPF program will be pinned to this path. If the eBPF program has already been pinned
	// and is already running in the kernel, then it will be loaded from this path.
	PinPath string

	// KProbeMaxActive - (kretprobes) With kretprobes, you can configure the maximum number of instances of the function that can be
	// probed simultaneously with maxactive. If maxactive is 0 it will be set to the default value: if CONFIG_PREEMPT is
	// enabled, this is max(10, 2*NR_CPUS); otherwise, it is NR_CPUS. For kprobes, maxactive is ignored.
	KProbeMaxActive int

	// KprobeAttachMethod - Method to use for attaching the kprobe. Either use perfEventOpen ABI or kprobe events
	KprobeAttachMethod KprobeAttachMethod

	// UprobeAttachMethod - Method to use for attaching the uprobe. Either use perfEventOpen ABI or uprobe events
	UprobeAttachMethod AttachMethod

	// UprobeOffset is added to UAddress or the resolved symbol's file offset.
	UprobeOffset uint64

	// ProbeRetry - Defines the number of times that the probe will retry to attach / detach on error.
	ProbeRetry uint

	// ProbeRetryDelay - Defines the delay to wait before the probe should retry to attach / detach on error.
	ProbeRetryDelay time.Duration

	// BinaryPath - (uprobes) A Uprobe is attached to a specific symbol in a user space binary. The offset is
	// automatically computed for the symbol name provided in the uprobe section ( SEC("uprobe/[symbol_name]") ).
	BinaryPath string

	// CGroupPath - (cgroup family programs) All CGroup programs are attached to a CGroup (v2). This field provides the
	// path to the CGroup to which the probe should be attached. The attach type is determined by the section.
	CGroupPath string

	// SocketFD - (socket filter) Socket filter programs are bound to a socket and filter the packets they receive
	// before they reach user space. The probe will be bound to the provided file descriptor
	SocketFD int

	// IfIndex - (TC classifier & XDP) Interface index used to identify the interface on which the probe will be
	// attached. If not set, fall back to `IfName`.
	IfIndex int

	// IfName - (TC Classifier & XDP) Interface name on which the probe will be attached.
	IfName string

	// IfIndexNetns - (TC Classifier & XDP) Network namespace in which the network interface lives. If this value is
	// provided, then IfIndexNetnsID is required too.
	// WARNING: it is up to the caller of "Probe.Start()" to close this netns handle. Failing to close this handle may
	// lead to leaking the network namespace. This handle can be safely closed once "Probe.Start()" returns.
	IfIndexNetns uint64

	// IfIndexNetnsID - (TC Classifier & XDP) Network namespace ID associated of the IfIndexNetns handle. If this value
	// is provided, then IfIndexNetns is required too.
	// WARNING: it is up to the caller of "Probe.Start()" to call "manager.CleanupNetworkNamespace()" once the provided
	// IfIndexNetnsID is no longer needed. Failing to call this cleanup function may lead to leaking the network
	// namespace. Remember that "manager.CleanupNetworkNamespace()" will close the netlink socket opened with the netns
	// handle provided above. If you want to start the probe again, you'll need to provide a new valid netns handle so
	// that a new netlink socket can be created in that namespace.
	IfIndexNetnsID uint32

	// XDPAttachMode - (XDP) XDP attach mode. If not provided the kernel will automatically select the best available
	// mode.
	XDPAttachMode XdpAttachMode

	// NetworkDirection - (TC classifier) Network traffic direction of the classifier. Can be either Ingress or Egress. Keep
	// in mind that if you are hooking on the host side of a virtual ethernet pair, Ingress and Egress are inverted.
	NetworkDirection TrafficType

	// TCFilterHandle - (TC classifier) defines the handle to use when loading the classifier. Leave unset to let the kernel decide which handle to use.
	TCFilterHandle uint32

	// TCFilterPrio - (TC classifier) defines the priority of the classifier added to the clsact qdisc. Defaults to DefaultTCFilterPriority.
	TCFilterPrio uint16

	// TCCleanupQDisc - (TC classifier) defines if the manager should clean up the clsact qdisc when a probe is unloaded
	TCCleanupQDisc bool

	// TCFilterProtocol - (TC classifier) defines the protocol to match in order to trigger the classifier. Defaults to
	// ETH_P_ALL.
	TCFilterProtocol uint16

	// SamplePeriod - (Perf event) This parameter defines when the perf_event eBPF program is triggered. When SamplePeriod > 0
	// the program will be triggered every SamplePeriod events.
	SamplePeriod int

	// SampleFrequency - (Perf event) This parameter defines when the perf_event eBPF program is triggered. When
	// SampleFrequency > 0, SamplePeriod is ignored and the eBPF program is triggered at the requested frequency.
	SampleFrequency int

	// PerfEventType - (Perf event) This parameter defines the type of the perf_event program. Allowed values are
	// unix.PERF_TYPE_HARDWARE and unix.PERF_TYPE_SOFTWARE
	PerfEventType int

	// PerfEventPID - (Perf event, uprobes) This parameter defines the PID for which the program should be triggered.
	// Do not set this value to monitor the whole host.
	PerfEventPID int

	// PerfEventConfig - (Perf event) This parameter defines which software or hardware event is being monitored. See the
	// PERF_COUNT_SW_* and PERF_COUNT_HW_* constants in the unix package.
	PerfEventConfig int

	// PerfEventCPUCount - (Perf event) This parameter defines the number of CPUs to monitor. If not set, defaults to
	// runtime.NumCPU(). Disclaimer: in containerized environment and depending on the CPU affinity of the program
	// holding the manager, runtime.NumCPU might not return the real CPU count of the host.
	PerfEventCPUCount int
}

// GetEbpfFuncName - Returns EbpfFuncName with the UID as a postfix if the Probe was copied
func (p *Probe) GetEbpfFuncName() string {
	if p.CopyProgram {
		return fmt.Sprintf("%s_%s", p.EbpfFuncName, p.UID)
	}
	return p.EbpfFuncName
}

// Copy - Returns a copy of the current probe instance. Only the exported fields are copied.
func (p *Probe) Copy() *Probe {
	return &Probe{
		UID:                p.UID,
		EbpfFuncName:       p.EbpfFuncName,
		Section:            p.Section,
		AttachToFuncName:   p.AttachToFuncName,
		UAddress:           p.UAddress,
		AttachPID:          p.AttachPID,
		LinkPinPath:        p.LinkPinPath,
		Ifindex:            p.Ifindex,
		Ifname:             p.Ifname,
		IfindexNetns:       p.IfindexNetns,
		SkipLoopback:       p.SkipLoopback,
		CopyProgram:        p.CopyProgram,
		KeepProgramSpec:    p.KeepProgramSpec,
		SyscallFuncName:    p.SyscallFuncName,
		MatchFuncName:      p.MatchFuncName,
		HookFuncName:       p.HookFuncName,
		TracepointCategory: p.TracepointCategory,
		TracepointName:     p.TracepointName,
		Enabled:            p.Enabled,
		PinPath:            p.PinPath,
		KProbeMaxActive:    p.KProbeMaxActive,
		KprobeAttachMethod: p.KprobeAttachMethod,
		UprobeAttachMethod: p.UprobeAttachMethod,
		UprobeOffset:       p.UprobeOffset,
		ProbeRetry:         p.ProbeRetry,
		ProbeRetryDelay:    p.ProbeRetryDelay,
		BinaryPath:         p.BinaryPath,
		CGroupPath:         p.CGroupPath,
		SocketFD:           p.SocketFD,
		IfIndex:            p.IfIndex,
		IfName:             p.IfName,
		IfIndexNetns:       p.IfIndexNetns,
		IfIndexNetnsID:     p.IfIndexNetnsID,
		XDPAttachMode:      p.XDPAttachMode,
		NetworkDirection:   p.NetworkDirection,
		TCFilterHandle:     p.TCFilterHandle,
		TCFilterPrio:       p.TCFilterPrio,
		TCCleanupQDisc:     p.TCCleanupQDisc,
		TCFilterProtocol:   p.TCFilterProtocol,
		SamplePeriod:       p.SamplePeriod,
		SampleFrequency:    p.SampleFrequency,
		PerfEventType:      p.PerfEventType,
		PerfEventPID:       p.PerfEventPID,
		PerfEventConfig:    p.PerfEventConfig,
		PerfEventCPUCount:  p.PerfEventCPUCount,
	}
}

// GetLastError - Returns the last error that the probe encountered
func (p *Probe) GetLastError() error {
	return p.lastError
}

// ID returns the system-wide unique ID for this program
func (p *Probe) ID() uint32 {
	p.stateLock.RLock()
	defer p.stateLock.RUnlock()
	return uint32(p.systemWideID)
}

// IsRunning - Returns true if the probe was successfully initialized, started and is currently running or paused.
func (p *Probe) IsRunning() bool {
	p.stateLock.RLock()
	defer p.stateLock.RUnlock()
	return p.state == running || p.state == paused
}

// IsInitialized - Returns true if the probe was successfully initialized.
func (p *Probe) IsInitialized() bool {
	p.stateLock.RLock()
	defer p.stateLock.RUnlock()
	return p.state >= initialized
}

// Test - Triggers the probe with the provided test data. Returns the length of the output, the raw output or an error.
func (p *Probe) Test(in []byte) (uint32, []byte, error) {
	return p.program.Test(in)
}

// Benchmark - Benchmark runs the Program with the given input for a number of times and returns the time taken per
// iteration.
//
// Returns the result of the last execution of the program and the time per run or an error. reset is called whenever
// the benchmark syscall is interrupted, and should be set to testing.B.ResetTimer or similar.
func (p *Probe) Benchmark(in []byte, repeat int, reset func()) (uint32, time.Duration, error) {
	return p.program.Benchmark(in, repeat, reset)
}

// initWithOptions - Initializes a probe with options
func (p *Probe) initWithOptions(manager *Manager, manualLoadNeeded bool, checkPin bool) error {
	if !p.Enabled {
		p.cleanupProgramSpec()
		return nil
	}

	p.stateLock.Lock()
	defer p.stateLock.Unlock()
	p.manualLoadNeeded = manualLoadNeeded
	p.checkPin = checkPin
	return p.internalInit(manager)
}

// init - Initialize a probe
func (p *Probe) init(manager *Manager) error {
	if !p.Enabled {
		p.cleanupProgramSpec()
		return nil
	}
	p.stateLock.Lock()
	defer p.stateLock.Unlock()
	return p.internalInit(manager)
}

func (p *Probe) Program() *ebpf.Program {
	return p.program
}

func (p *Probe) internalInit(manager *Manager) error {
	if p.state >= initialized {
		return nil
	}

	p.netlinkSocketCache = manager.netlinkSocketCache
	if !manager.options.DiscardProgramSpecs {
		p.KeepProgramSpec = true
	}
	if err := p.normalizeLegacyFields(); err != nil {
		return err
	}
	p.state = reset
	// Load spec if necessary
	if p.manualLoadNeeded {
		prog, err := ebpf.NewProgramWithOptions(p.programSpec, manager.options.VerifierOptions.Programs)
		if err != nil {
			p.lastError = err
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				// include error twice to preserve context, and still allow unwrapping if desired
				return fmt.Errorf("verifier error loading new probe %v: %w\n%+v", p.GetIdentificationPair(), err, ve)
			}
			return fmt.Errorf("couldn't load new probe %v: %w", p.GetIdentificationPair(), err)
		}
		p.program = prog
	}

	// Retrieve eBPF program if one isn't already set
	if p.program == nil {
		if p.program, p.lastError = manager.getProbeProgram(p.GetEbpfFuncName()); p.lastError != nil {
			return fmt.Errorf("couldn't find program %s: %w", p.GetEbpfFuncName(), ErrUnknownSectionOrFuncName)
		}
		p.checkPin = true
	}

	if p.programSpec == nil {
		if p.programSpec, p.lastError = manager.getProbeProgramSpec(p.GetEbpfFuncName()); p.lastError != nil {
			return fmt.Errorf("couldn't find program spec %s: %w", p.GetEbpfFuncName(), ErrUnknownSectionOrFuncName)
		}
	}
	// Probe-local section overrides must not change another probe's shared spec.
	if p.Section != "" && p.Section != p.programSpec.SectionName {
		p.programSpec = p.programSpec.Copy()
		p.programSpec.SectionName = p.Section
	}

	if p.programSpec.Type == ebpf.SchedCLS {
		// sanity check
		if p.NetworkDirection != Egress && p.NetworkDirection != Ingress {
			return fmt.Errorf("%s has an invalid configuration: %w", p.GetIdentificationPair(), ErrNoNetworkDirection)
		}
	}

	if p.checkPin {
		// Pin program if needed
		if p.PinPath != "" {
			if err := p.program.Pin(p.PinPath); err != nil {
				p.lastError = err
				return fmt.Errorf("couldn't pin program %s at %s: %w", p.GetEbpfFuncName(), p.PinPath, err)
			}
		}
		p.checkPin = false
	}

	// Update syscall function name with the correct arch prefix
	if p.HookFuncName == "" && p.AttachToFuncName != "" {
		p.HookFuncName = p.AttachToFuncName
		if strings.HasPrefix(p.programSpec.SectionName, "kprobe/") || strings.HasPrefix(p.programSpec.SectionName, "kretprobe/") {
			resolved, err := GetSyscallFnNameWithSymFile(p.AttachToFuncName, manager.options.SymFile)
			if err == nil {
				p.HookFuncName = resolved
			}
			// Leave missing hook points to Attach and the activation selectors. Optional
			// probes may legitimately be absent on an older kernel.
		}
	}

	if p.SyscallFuncName != "" && len(p.HookFuncName) == 0 {
		var err error
		p.HookFuncName, err = GetSyscallFnNameWithSymFile(p.SyscallFuncName, manager.options.SymFile)
		if err != nil {
			p.lastError = err
			return err
		}
	}

	if p.programSpec.Type == ebpf.Kprobe {
		progType, _, _ := strings.Cut(p.programSpec.SectionName, "/")
		switch progType {
		case "kprobe":
			p.kprobeType = kprobe
		case "kretprobe":
			p.kprobeType = kprobe
			p.isReturnProbe = true
		case "uprobe":
			p.kprobeType = uprobe
		case "uretprobe":
			p.kprobeType = uprobe
			p.isReturnProbe = true
		}

		// Find function name match if required
		if p.MatchFuncName != "" && len(p.HookFuncName) == 0 {
			// if this is a kprobe or a kretprobe, look for the symbol now
			if p.kprobeType == kprobe {
				var err error
				p.HookFuncName, err = FindFilterFunction(p.MatchFuncName)
				if err != nil {
					p.lastError = err
					return err
				}
			}
		}
	}

	if len(p.HookFuncName) == 0 {
		// default back to the AttachTo field in Program, as parsed by Cilium
		p.HookFuncName = p.programSpec.AttachTo
	}

	// resolve netns ID from netns handle
	if p.IfIndexNetns == 0 && p.IfIndexNetnsID != 0 || p.IfIndexNetns != 0 && p.IfIndexNetnsID == 0 {
		return fmt.Errorf("both IfIndexNetns and IfIndexNetnsID are required if one is provided (IfIndexNetns: %d IfIndexNetnsID: %d)", p.IfIndexNetns, p.IfIndexNetnsID)
	}

	// set default TC classifier priority
	if p.TCFilterPrio == 0 {
		p.TCFilterPrio = DefaultTCFilterPriority
	}

	// set default TC classifier protocol
	if p.TCFilterProtocol == 0 {
		p.TCFilterProtocol = unix.ETH_P_ALL
	}

	// Default max active value
	if p.KProbeMaxActive == 0 {
		p.KProbeMaxActive = manager.options.DefaultKProbeMaxActive
	}

	// Default retry
	if p.ProbeRetry == 0 {
		p.ProbeRetry = manager.options.DefaultProbeRetry
	}

	// Default retry delay
	if p.ProbeRetryDelay == 0 {
		p.ProbeRetryDelay = manager.options.DefaultProbeRetryDelay
	}

	// fetch system-wide program ID, if the feature is available
	if p.LinkPinPath != "" {
		pinned, err := link.LoadPinnedLink(p.LinkPinPath, nil)
		if err == nil {
			info, infoErr := pinned.Info()
			if infoErr != nil {
				_ = pinned.Close()
				return infoErr
			}
			program, progErr := ebpf.NewProgramFromID(info.Program)
			if progErr != nil {
				_ = pinned.Close()
				return progErr
			}
			p.program, p.progLink = program, pinned
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("load pinned link: %w", err)
		}
	}
	if p.program != nil {
		programInfo, err := p.program.Info()
		if err == nil {
			p.programTag = programInfo.Tag
			id, available := programInfo.ID()
			if available {
				p.systemWideID = int(id)
			}
		}
	}

	// set default kprobe attach method
	if p.KprobeAttachMethod == AttachKprobeMethodNotSet {
		p.KprobeAttachMethod = manager.options.DefaultKprobeAttachMethod
		if p.KprobeAttachMethod == AttachKprobeMethodNotSet {
			p.KprobeAttachMethod = AttachKprobeWithPerfEventOpen
		}
	}

	// set default uprobe attach method
	if p.UprobeAttachMethod == AttachMethodNotSet {
		p.UprobeAttachMethod = manager.options.DefaultUprobeAttachMethod
		if p.UprobeAttachMethod == AttachMethodNotSet {
			p.UprobeAttachMethod = AttachWithPerfEventOpen
		}
	}

	// update probe state
	p.state = initialized
	p.cleanupProgramSpec()
	return nil
}

// Attach - Attaches the probe to the right hook point in the kernel depending on the program type and the provided
// parameters.
func (p *Probe) Attach() error {
	return internal.Retry(func() error {
		p.attachRetryAttempt++
		err := p.attach()
		if err == nil {
			return nil
		}

		// not available, not a temporary error
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.EINVAL) {
			return nil
		}

		return err
	}, p.getRetryAttemptCount(), p.ProbeRetryDelay)
}

func (p *Probe) Pause() error {
	return p.pause()
}

func (p *Probe) Resume() error {
	return p.resume()
}

// attach - Thread unsafe version of attach
func (p *Probe) attach() error {
	p.stateLock.Lock()
	defer p.stateLock.Unlock()
	if p.state >= paused || !p.Enabled {
		return nil
	}
	if p.state < initialized {
		if p.lastError == nil {
			p.lastError = ErrProbeNotInitialized
		}
		return ErrProbeNotInitialized
	}

	p.attachPID = Getpid()
	if p.progLink != nil && p.LinkPinPath != "" {
		p.state = running
		return nil
	}

	// Per program type start
	var err error
	switch p.programSpec.Type {
	case ebpf.UnspecifiedProgram:
		err = fmt.Errorf("invalid program type, make sure to use the right section prefix: %w", ErrSectionFormat)
	case ebpf.Kprobe:
		switch p.kprobeType {
		case kprobe:
			err = p.attachKprobe()
		case uprobe:
			err = p.attachUprobe()
		}
	case ebpf.TracePoint:
		err = p.attachTracepoint()
	case ebpf.RawTracepoint, ebpf.RawTracepointWritable:
		err = p.attachRawTracepoint()
	case ebpf.CGroupDevice, ebpf.CGroupSKB, ebpf.CGroupSock, ebpf.CGroupSockAddr, ebpf.CGroupSockopt, ebpf.CGroupSysctl, ebpf.SockOps:
		err = p.attachCGroup()
	case ebpf.SocketFilter:
		err = p.attachSocket()
	case ebpf.SchedCLS:
		err = p.attachTCCLS()
	case ebpf.XDP:
		err = p.attachXDP()
	case ebpf.LSM:
		err = p.attachLSM()
	case ebpf.PerfEvent:
		err = p.attachPerfEvent()
	case ebpf.Tracing:
		err = p.attachTracing()
	default:
		err = fmt.Errorf("program type %s not implemented yet", p.programSpec.Type)
	}
	if err == nil && p.LinkPinPath != "" {
		if pinned, ok := p.progLink.(interface{ Pin(string) error }); ok {
			err = pinned.Pin(p.LinkPinPath)
		} else {
			err = fmt.Errorf("attachment does not support link pinning: %w", ErrNotSupported)
		}
	}
	if err != nil {
		p.lastError = err
		// Clean up any progress made in the attach attempt
		_ = p.stop(false)
		return fmt.Errorf("couldn't start probe %s: %w", p.GetIdentificationPair(), err)
	}

	// update probe state
	p.state = running
	p.attachRetryAttempt = p.getRetryAttemptCount()
	return nil
}

func (p *Probe) Iterator() (io.ReadCloser, error) {
	p.stateLock.RLock()
	defer p.stateLock.RUnlock()
	if p.state <= paused || !p.Enabled {
		return nil, ErrManagerNotStarted
	}
	if p.programSpec.AttachType != ebpf.AttachTraceIter {
		return nil, fmt.Errorf("invalid program attach type %s", p.programSpec.AttachType)
	}
	it, ok := p.progLink.(*link.Iter)
	if !ok {
		return nil, fmt.Errorf("invalid program attach type %T", p.progLink)
	}
	return it.Open()
}

// cleanupProgramSpec - Cleans up the internal ProgramSpec attribute to free up some memory
func (p *Probe) cleanupProgramSpec() {
	if p.KeepProgramSpec {
		return
	}
	cleanupProgramSpec(p.programSpec)
}

func (p *Probe) pause() error {
	p.stateLock.Lock()
	defer p.stateLock.Unlock()
	if p.state <= paused || !p.Enabled {
		return nil
	}

	v, ok := p.progLink.(pauser)
	if ok {
		if err := v.Pause(); err != nil {
			p.lastError = err
			return fmt.Errorf("error pausing probe %s: %w", p.GetIdentificationPair(), err)
		}
		p.state = paused
		return nil
	}

	if p.bypassIndex > 0 && p.bypassMap != nil {
		if err := p.bypassMap.array.Update(p.bypassIndex, bypassValue, ebpf.UpdateExist); err != nil {
			return err
		}
		p.state = paused
		return nil
	}
	return nil
}

func (p *Probe) resume() error {
	p.stateLock.Lock()
	defer p.stateLock.Unlock()
	if p.state != paused || !p.Enabled {
		return nil
	}

	v, ok := p.progLink.(pauser)
	if ok {
		if err := v.Resume(); err != nil {
			p.lastError = err
			return fmt.Errorf("error resuming probe %s: %w", p.GetIdentificationPair(), err)
		}
		p.state = running
		return nil
	}

	if err := p.disableBypass(); err != nil {
		return err
	}
	p.state = running
	return nil
}

func (p *Probe) disableBypass() error {
	if p.bypassIndex > 0 && p.bypassMap != nil {
		return p.bypassMap.array.Update(p.bypassIndex, enableValue, ebpf.UpdateExist)
	}
	return nil
}

// Detach - Detaches the probe from its hook point depending on the program type and the provided parameters. This
// method does not close the underlying eBPF program, which means that Attach can be called again later.
func (p *Probe) Detach() error {
	p.stateLock.Lock()
	defer p.stateLock.Unlock()
	if p.state < paused || !p.Enabled {
		return nil
	}

	// detach from hook point
	err := p.detachRetry()

	// update state of the probe
	if err != nil {
		p.lastError = err
	} else {
		p.state = initialized
	}

	_ = p.disableBypass()
	return err
}

// detachRetry - Thread unsafe version of Detach with retry
func (p *Probe) detachRetry() error {
	return internal.Retry(p.detach, p.getRetryAttemptCount(), p.ProbeRetryDelay)
}

// detach - Thread unsafe version of Detach.
func (p *Probe) detach() error {
	err := p.program.Unpin()

	// Per program type cleanup
	switch p.programSpec.Type {
	case ebpf.UnspecifiedProgram:
		// nothing to do
		break
	case ebpf.SchedCLS:
		err = errors.Join(err, p.detachTCCLS())
	default:
		if p.progLink != nil {
			if p.LinkPinPath != "" {
				if pinned, ok := p.progLink.(interface{ Unpin() error }); ok {
					err = errors.Join(err, pinned.Unpin())
				}
			}
			err = errors.Join(err, p.progLink.Close())
			p.progLink = nil
		}
	}
	return err
}

// Stop - Detaches the probe from its hook point and close the underlying eBPF program.
func (p *Probe) Stop() error {
	p.stateLock.Lock()
	defer p.stateLock.Unlock()
	if p.state < paused || !p.Enabled {
		p.reset()
		return nil
	}
	return p.stop(true)
}

func (p *Probe) stop(saveStopError bool) error {
	// detach from hook point
	err := p.detachRetry()

	// close the loaded program
	if p.attachRetryAttempt >= p.getRetryAttemptCount() {
		err = errors.Join(err, p.program.Close())
	}

	// update state of the probe
	if saveStopError {
		p.lastError = errors.Join(p.lastError, err)
	}

	// Cleanup probe if stop was successful
	if err == nil && p.attachRetryAttempt >= p.getRetryAttemptCount() {
		p.reset()
	}
	if err != nil {
		return fmt.Errorf("couldn't stop probe %s: %w", p.GetIdentificationPair(), err)
	}
	return nil
}

// reset - Cleans up the internal fields of the probe
func (p *Probe) reset() {
	p.kprobeType = kprobe
	p.isReturnProbe = false
	p.netlinkSocketCache = nil
	p.program = nil
	p.programSpec = nil
	p.progLink = nil
	p.state = reset
	p.manualLoadNeeded = false
	p.checkPin = false
	p.attachPID = 0
	p.attachRetryAttempt = 0
	p.kprobeHookPointNotExist = false
	p.systemWideID = 0
	p.programTag = ""
	p.tcFilter = netlink.BpfFilter{}
	p.tcClsActQdisc = nil
}

func (p *Probe) getRetryAttemptCount() uint {
	return p.ProbeRetry + 1
}
