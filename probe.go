package manager

import (
	"fmt"
	"github.com/cilium/ebpf/link"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"errors"
	"github.com/avast/retry-go"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
)

// XdpAttachMode selects a way how XDP program will be attached to interface
type XdpAttachMode int

const (
	// XdpAttachModeNone stands for "best effort" - kernel automatically
	// selects best mode (would try Drv first, then fallback to Generic).
	// NOTE: Kernel will not fallback to Generic XDP if NIC driver failed
	//       to install XDP program.
	XdpAttachModeNone XdpAttachMode = 0
	// XdpAttachModeSkb is "generic", kernel mode, less performant comparing to native,
	// but does not requires driver support.
	XdpAttachModeSkb XdpAttachMode = 1 << 1
	// XdpAttachModeDrv is native, driver mode (support from driver side required)
	XdpAttachModeDrv XdpAttachMode = 1 << 2
	// XdpAttachModeHw suitable for NICs with hardware XDP support
	XdpAttachModeHw XdpAttachMode = 1 << 3
	// DefaultTCFilterPriority is the default TC filter priority if none were given
	DefaultTCFilterPriority = 50
)

type TrafficType uint16

func (tt TrafficType) String() string {
	switch tt {
	case Ingress:
		return "ingress"
	case Egress:
		return "egress"
	default:
		return fmt.Sprintf("TrafficType(%d)", tt)
	}
}

const (
	Ingress          = TrafficType(tc.HandleMinIngress)
	Egress           = TrafficType(tc.HandleMinEgress)
	clsactQdisc      = uint16(netlink.HANDLE_INGRESS >> 16)
	UnknownProbeType = ""
	ProbeType        = "p"
	RetProbeType     = "r"
)

type ProbeIdentificationPair struct {
	UID string
	//Section string
	EbpfFuncName string //在cilium/efbp v0.7.0里，返回的paramsspec中，改为以.o字节码中符号表函数名为索引的map，故这里改为matchfunName。 section信息无法使用
}

func (pip ProbeIdentificationPair) String() string {
	return fmt.Sprintf("{UID:%s, EbpfFuncName:%s}", pip.UID, pip.EbpfFuncName)
}

// Matches - Returns true if the identification pair (probe uid, probe section) matches.
func (pip ProbeIdentificationPair) Matches(id ProbeIdentificationPair) bool {
	return pip.UID == id.UID && pip.EbpfFuncName == id.EbpfFuncName
}

// Probe - Main eBPF probe wrapper. This structure is used to store the required data to attach a loaded eBPF
// program to its hook point.
type Probe struct {
	manager            *Manager
	program            *ebpf.Program
	programSpec        *ebpf.ProgramSpec
	attachPID          int
	link               link.Link
	tcFilter           netlink.BpfFilter
	tcClsActQdisc      netlink.Qdisc
	state              state
	stateLock          sync.RWMutex
	manualLoadNeeded   bool
	checkPin           bool
	funcName           string //目标hook对象的函数名；uprobe中，若为空，则使用offset。
	AttachPID          int    // pid to attach, only for uprobe .
	attachRetryAttempt uint

	// TCFilterHandle - (TC classifier) defines the handle to use when loading the classifier. Leave unset to let the kernel decide which handle to use.
	TCFilterHandle uint32

	// TCFilterPrio - (TC classifier) defines the priority of the classifier added to the clsact qdisc. Defaults to DefaultTCFilterPriority.
	TCFilterPrio uint16

	// TCCleanupQDisc - (TC classifier) defines if the manager should cleanup the clsact qdisc when a probe is unloaded
	TCCleanupQDisc bool

	// TCFilterProtocol - (TC classifier) defines the protocol to match in order to trigger the classifier. Defaults to
	// ETH_P_ALL.
	TCFilterProtocol uint16

	// lastError - stores the last error that the probe encountered, it is used to surface a more useful error message
	// when one of the validators (see Options.ActivatedProbes) fails.
	lastError error

	// UID - (optional) this field can be used to identify your probes when the same eBPF program is used on multiple
	// hook points. Keep in mind that the pair (probe section, probe UID) needs to be unique
	// system-wide for the kprobes and uprobes registration to work.
	UID string

	// Section - Section of the program, as defined in its section SEC("[section]"). This section is therefore made of
	// a prefix
	//
	// NOTE: 字节码中段信息不被新版ebpf库programSpec map作为索引。 v0.7.0
	// 故，不能作为programSpec[]的索引来使用。索引改用MatchFuncName
	Section string

	// CopyProgram - When enabled, this option will make a unique copy of the program section for the current program
	CopyProgram bool

	// EbpfFuncName - Name of the syscall on which the program should be hooked. As the exact kernel symbol may
	// differ from one kernel version to the other, the right prefix will be computed automatically at runtime.
	// If a syscall name is not provided, the section name (without its probe type prefix) is assumed to be the
	// hook point.
	EbpfFuncName string

	// AttachToFuncName - Pattern used to find the function(s) to attach to
	// FOR KPROBES: When this option is activated, the provided pattern is matched against the list of available symbols
	// in /sys/kernel/debug/tracing/available_filter_functions. If the exact function does not exist, then the first
	// symbol matching the provided pattern will be used. This option requires debugfs.
	//
	// FOR UPROBES: When this option is activated, the provided pattern is matched the list of symbols in the symbol
	// table of the provided elf binary. If the exact function does not exist, then the first symbol matching the
	// provided pattern will be used.
	AttachToFuncName string

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

	// UprobeOffset - If UprobeOffset is provided, the uprobe will be attached to it directly without looking for the
	// symbol in the elf binary. If the file is a non-PIE executable, the provided address must be a virtual address,
	// otherwise it must be an offset relative to the file load address.
	UprobeOffset uint64

	// ProbeRetry - Defines the number of times that the probe will retry to attach / detach on error.
	ProbeRetry uint

	// ProbeRetryDelay - Defines the delay to wait before the probe should retry to attach / detach on error.
	ProbeRetryDelay time.Duration

	// BinaryPath - (uprobes) A Uprobe is attached to a specific symbol in a user space binary. The offset is
	// automatically computed for the symbol name provided in the uprobe section ( SEC("uprobe/[symbol_name]") ).
	BinaryPath string

	// CGrouPath - (cgroup family programs) All CGroup programs are attached to a CGroup (v2). This field provides the
	// path to the CGroup to which the probe should be attached. The attach type is determined by the section.
	CGroupPath string

	// SocketFD - (socket filter) Socket filter programs are bound to a socket and filter the packets they receive
	// before they reach user space. The probe will be bound to the provided file descriptor
	SocketFD int

	// Ifindex - (TC classifier & XDP) Interface index used to identify the interface on which the probe will be
	// attached. If not set, fall back to Ifname.
	Ifindex int32

	// Ifname - (TC Classifier & XDP) Interface name on which the probe will be attached.
	Ifname string

	// IfindexNetns - (TC Classifier & XDP) Network namespace in which the network interface lives
	IfindexNetns uint64

	// XDPAttachMode - (XDP) XDP attach mode. If not provided the kernel will automatically select the best available
	// mode.
	XDPAttachMode XdpAttachMode

	// NetworkDirection - (TC classifier) Network traffic direction of the classifier. Can be either Ingress or Egress. Keep
	// in mind that if you are hooking on the host side of a virtuel ethernet pair, Ingress and Egress are inverted.
	NetworkDirection TrafficType

	// SkipLoopback loopback devices are special, some tc probes should be skipped ,see https://github.com/aquasecurity/tracee/blob/fcdb1d6171ef75b22248253a51b581856328f75c/pkg/ebpf/probes/probes.go#L322 for more detail.
	SkipLoopback bool
	// tcObject - (TC classifier) TC object created when the classifier was attached. It will be reused to delete it on
	// exit.
	tcObject *tc.Object
}

// Copy - Returns a copy of the current probe instance. Only the exported fields are copied.
func (p *Probe) Copy() *Probe {
	return &Probe{
		UID:              p.UID,
		Section:          p.Section,
		AttachToFuncName: p.AttachToFuncName,
		EbpfFuncName:     p.EbpfFuncName,
		Enabled:          p.Enabled,
		PinPath:          p.PinPath,
		KProbeMaxActive:  p.KProbeMaxActive,
		BinaryPath:       p.BinaryPath,
		CGroupPath:       p.CGroupPath,
		SocketFD:         p.SocketFD,
		Ifindex:          p.Ifindex,
		Ifname:           p.Ifname,
		IfindexNetns:     p.IfindexNetns,
		XDPAttachMode:    p.XDPAttachMode,
		NetworkDirection: p.NetworkDirection,
		ProbeRetry:       p.ProbeRetry,
		ProbeRetryDelay:  p.ProbeRetryDelay,
	}
}

// checkField - Returns the last error that the probe encountered
func (p *Probe) checkField() error {
	if p.EbpfFuncName == "" || p.Section == "" {
		return errors.New(fmt.Sprintf("EbpfFuncName:%s, Section:%s cant be null.", p.EbpfFuncName, p.Section))
	}

	//regex match 如果不是kprobe或uprobe，则直接允许为空
	regexStr := `([ku](ret)?probe/)`
	fnRegex := regexp.MustCompile(regexStr)
	match := fnRegex.FindAllString(p.Section, -1)
	if len(match) <= 0 {
		return nil
	}

	if p.AttachToFuncName == "" {
		return errors.New(fmt.Sprintf("AttachToFuncName:%s cant be null.", p.AttachToFuncName))
	}
	return nil
}

// GetLastError - Returns the last error that the probe encountered
func (p *Probe) GetLastError() error {
	return p.lastError
}

// IdentificationPairMatches - Returns true if the identification pair (probe uid, probe section) matches.
func (p *Probe) IdentificationPairMatches(id ProbeIdentificationPair) bool {
	return p.GetIdentificationPair().Matches(id)
}

// GetIdentificationPair - Returns the identification pair (probe section, probe UID)
func (p *Probe) GetIdentificationPair() ProbeIdentificationPair {
	return ProbeIdentificationPair{p.UID, p.EbpfFuncName}
}

// IsRunning - Returns true if the probe was successfully initialized, started and is currently running.
func (p *Probe) IsRunning() bool {
	p.stateLock.RLock()
	defer p.stateLock.RUnlock()
	return p.state == running
}

// IsInitialized - Returns true if the probe was successfully initialized, started and is currently running.
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

// InitWithOptions - Initializes a probe with options
func (p *Probe) InitWithOptions(manager *Manager, manualLoadNeeded bool, checkPin bool) error {
	if !p.Enabled {
		return nil
	}
	p.manager = manager
	p.stateLock.Lock()
	defer p.stateLock.Unlock()
	p.state = reset
	p.manualLoadNeeded = manualLoadNeeded
	p.checkPin = checkPin
	return p.init()
}

// Init - Initialize a probe
func (p *Probe) Init(manager *Manager) error {
	if !p.Enabled {
		return nil
	}
	p.manager = manager
	p.stateLock.Lock()
	defer p.stateLock.Unlock()
	p.state = reset
	return p.init()
}

func (p *Probe) Program() *ebpf.Program {
	return p.program
}

// init - Internal initialization function
func (p *Probe) init() error {
	err := p.checkField()
	if err != nil {
		return err
	}

	// Load spec if necessary
	if p.manualLoadNeeded {
		prog, err := ebpf.NewProgramWithOptions(p.programSpec, p.manager.options.VerifierOptions.Programs)
		if err != nil {
			p.lastError = err
			return errors.New(fmt.Sprintf("error:%v , couldn't load new probe %v", err, p.GetIdentificationPair()))
		}
		p.program = prog
	}

	// override matchFuncName based on the CopyProgram parameter
	matchFuncName := p.EbpfFuncName
	if p.CopyProgram {
		matchFuncName += p.UID
	}

	// Retrieve eBPF program if one isn't already set
	if p.program == nil {
		prog, ok := p.manager.collection.Programs[matchFuncName]
		if !ok {
			p.lastError = ErrUnknownMatchFuncName
			return fmt.Errorf("error:%v,couldn't find program  %s ", ErrUnknownMatchFuncName, matchFuncName)
		}
		p.program = prog
		p.checkPin = true
	}

	if p.programSpec == nil {
		if p.programSpec, p.lastError = p.manager.getProbeProgramSpec(matchFuncName); p.lastError != nil {
			return fmt.Errorf("error:%v, couldn't find program spec %s", ErrUnknownMatchFuncSpec, matchFuncName)
		}
	}

	if p.checkPin {
		// Pin program if needed
		if p.PinPath != "" {
			if err := p.program.Pin(p.PinPath); err != nil {
				p.lastError = err
				return errors.New(fmt.Sprintf("error:%v , couldn't pin program %s at %s", err, matchFuncName, p.PinPath))
			}
		}
		p.checkPin = false
	}

	// Find function name match if required
	var kProbe = false
	if strings.HasPrefix(p.Section, "kretprobe/") || (strings.HasPrefix(p.Section, "kprobe/")) {
		var err error
		p.funcName, err = FindFilterFunction(p.Section)
		if err != nil {
			p.lastError = err
			return err
		}
		kProbe = true
	}

	if kProbe {
		// Update syscall function name with the correct arch prefix
		var err error
		p.funcName, err = GetSyscallFnNameWithSymFile(p.AttachToFuncName, p.manager.options.SymFile)
		if err != nil {
			p.lastError = err
			return err
		}
	}

	// Resolve interface index if one is provided
	if p.Ifindex == 0 && p.Ifname != "" {
		inter, err := net.InterfaceByName(p.Ifname)
		if err != nil {
			p.lastError = err
			return errors.New(fmt.Sprintf("error:%v , couldn't find interface %v", err, p.Ifname))
		}

		// Check if interface is loopback
		isNetIfaceLo := inter.Flags&net.FlagLoopback == net.FlagLoopback
		if isNetIfaceLo && p.SkipLoopback {
			return fmt.Errorf("error:%v , interface %v is loopback and SkipLoopback is set", ErrLoopbackDisabled, p.Ifname)
		}

		p.Ifindex = int32(inter.Index)
	}

	// Default max active value
	if p.KProbeMaxActive == 0 {
		p.KProbeMaxActive = p.manager.options.DefaultKProbeMaxActive
	}

	// Default retry
	if p.ProbeRetry == 0 {
		if p.manager.options.DefaultProbeRetry > 0 {
			p.ProbeRetry = p.manager.options.DefaultProbeRetry
		}
	}
	// account for the initial attempt
	p.ProbeRetry++

	// Default retry delay
	if p.ProbeRetryDelay == 0 {
		p.ProbeRetryDelay = p.manager.options.DefaultProbeRetryDelay
	}

	// update probe state
	p.state = initialized
	return nil
}

// Attach - Attaches the probe to the right hook point in the kernel depending on the program type and the provided
// parameters.
func (p *Probe) Attach() error {
	return retry.Do(func() error {
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
	}, retry.Attempts(p.ProbeRetry), retry.Delay(p.ProbeRetryDelay), retry.LastErrorOnly(true))
}

// attach - Thread unsafe version of attach
func (p *Probe) attach() error {
	p.stateLock.Lock()
	defer p.stateLock.Unlock()
	if p.state >= running || !p.Enabled {
		return nil
	}
	if p.state < initialized {
		if p.lastError == nil {
			p.lastError = ErrProbeNotInitialized
		}
		return ErrProbeNotInitialized
	}

	// Per program type start
	var err error
	switch p.programSpec.Type {
	case ebpf.UnspecifiedProgram:
		err = fmt.Errorf("error:%v, %s", ErrSectionFormat, "invalid program type, make sure to use the right section prefix")
	case ebpf.Kprobe:
		err = p.attachKprobe()
	case ebpf.TracePoint:
		err = p.attachTracepoint()
	case ebpf.CGroupDevice, ebpf.CGroupSKB, ebpf.CGroupSock, ebpf.CGroupSockAddr, ebpf.CGroupSockopt, ebpf.CGroupSysctl:
		err = p.attachCGroup()
	case ebpf.SocketFilter:
		err = p.attachSocket()
	case ebpf.SchedCLS:
		err = p.attachTCCLS()
	case ebpf.XDP:
		err = p.attachXDP()
	case ebpf.RawTracepoint:
		err = p.attachRawTracepoint()
	default:
		err = fmt.Errorf("program type %s not implemented yet", p.programSpec.Type)
	}
	if err != nil {
		p.lastError = err
		// Clean up any progress made in the attach attempt
		_ = p.stop(false)
		return errors.New(fmt.Sprintf("error:%v , couldn't start probe %s", err, p.EbpfFuncName))
	}

	// update probe state
	p.state = running
	p.attachRetryAttempt = p.ProbeRetry
	return nil
}

// Detach - Detaches the probe from its hook point depending on the program type and the provided parameters. This
// method does not close the underlying eBPF program, which means that Attach can be called again later.
func (p *Probe) Detach() error {
	p.stateLock.Lock()
	defer p.stateLock.Unlock()
	if p.state < running || !p.Enabled {
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

	return err
}

// detachRetry - Thread unsafe version of Detach with retry
func (p *Probe) detachRetry() error {
	return retry.Do(p.detach, retry.Attempts(p.ProbeRetry), retry.Delay(p.ProbeRetryDelay), retry.LastErrorOnly(true))
}

// detach - Thread unsafe version of Detach.
func (p *Probe) detach() error {
	var err error
	// Remove pin if needed
	if p.PinPath != "" {
		err = ConcatErrors(err, os.Remove(p.PinPath))
	}

	// Shared with all probes: close the perf event file descriptor
	if p.link != nil {
		err = p.link.Close()
	}
	// Per program type cleanup
	switch p.programSpec.Type {
	case ebpf.UnspecifiedProgram:
		// nothing to do
		break
	case ebpf.Kprobe:
	case ebpf.CGroupDevice, ebpf.CGroupSKB, ebpf.CGroupSock, ebpf.CGroupSockAddr, ebpf.CGroupSockopt, ebpf.CGroupSysctl:
	case ebpf.SocketFilter:
		err = ConcatErrors(err, p.detachSocket())
	case ebpf.SchedCLS:
		err = ConcatErrors(err, p.detachTCCLS())
	case ebpf.XDP:
		err = ConcatErrors(err, p.detachXDP())
	default:
		// unsupported section, nothing to do either
		break
	}
	return err
}

// Stop - Detaches the probe from its hook point and close the underlying eBPF program.
func (p *Probe) Stop() error {
	p.stateLock.Lock()
	defer p.stateLock.Unlock()
	if p.state < running || !p.Enabled {
		p.reset()
		return nil
	}
	return p.stop(true)
}

func (p *Probe) stop(saveStopError bool) error {
	// detach from hook point
	err := p.detachRetry()

	// close the loaded program
	if p.attachRetryAttempt >= p.ProbeRetry {
		err = ConcatErrors(err, p.program.Close())
	}
	// update state of the probe
	if saveStopError {
		p.lastError = ConcatErrors(p.lastError, err)
	}

	// Cleanup probe if stop was successful
	if err == nil {
		if p.attachRetryAttempt >= p.ProbeRetry {
			p.reset()
		}
		return nil
	}
	return errors.New(fmt.Sprintf("error:%v , couldn't stop probe %s", err, p.EbpfFuncName))
}

// reset - Cleans up the internal fields of the probe
func (p *Probe) reset() {
	p.manager = nil
	p.program = nil
	p.programSpec = nil
	//p.perfEventFD = nil
	p.link = nil
	p.state = reset
	p.manualLoadNeeded = false
	p.checkPin = false
	p.funcName = ""
	p.AttachPID = 0
	p.attachRetryAttempt = 0
}

// attachKprobe - Attaches the probe to its kprobe
func (p *Probe) attachKprobe() error {
	// Prepare kprobe_events line parameters
	var err error
	funcName := p.funcName
	isRet := false
	if strings.HasPrefix(p.Section, "kretprobe/") {
		isRet = true
	} else if strings.HasPrefix(p.Section, "kprobe/") {
		isRet = false
	} else {
		// this might actually be a Uprobe
		return p.attachUprobe()
	}

	var kp link.Link
	if isRet {
		kp, err = link.Kretprobe(funcName, p.program, nil)
	} else {
		kp, err = link.Kprobe(funcName, p.program, nil)
	}

	if err != nil {
		return fmt.Errorf("opening Kprobe: %s, funcName:%s, isRet:%t, section:%s", err, funcName, isRet, p.Section)
	}
	p.link = kp
	return nil
}

// attachTracepoint - Attaches the probe to its tracepoint
func (p *Probe) attachTracepoint() error {
	// Parse section
	traceGroup := strings.SplitN(p.programSpec.SectionName, "/", 3)
	if len(traceGroup) != 3 {
		return fmt.Errorf("error:%v, expected SEC(\"tracepoint/[category]/[name]\") got %s", ErrSectionFormat, p.programSpec.SectionName)
	}
	category := traceGroup[1]
	name := traceGroup[2]

	kp, err := link.Tracepoint(category, name, p.program, nil)
	if err != nil {
		return errors.New(fmt.Sprintf("error:%v , couldn's activate tracepoint %s, matchFuncName:%s", err, p.Section, p.EbpfFuncName))
	}
	p.link = kp
	return nil
}

// attachUprobe - Attaches the probe to its Uprobe
func (p *Probe) attachUprobe() error {
	// Prepare uprobe_events line parameters
	//var funcName string
	var isRet bool
	if strings.HasPrefix(p.Section, "uretprobe/") {
		//funcName = strings.TrimPrefix(p.Section, "uretprobe/")
		isRet = true
	} else if strings.HasPrefix(p.Section, "uprobe/") {
		//funcName = strings.TrimPrefix(p.Section, "uprobe/")
	} else {
		// unknown type
		return fmt.Errorf("error:%v, program type unrecognized in section %v", ErrSectionFormat, p.Section)
	}

	// compute the offset if it was not provided
	if p.UprobeOffset == 0 {
		p.funcName = p.AttachToFuncName
	}

	ex, err := link.OpenExecutable(p.BinaryPath)
	if err != nil {
		return errors.New(fmt.Sprintf("error:%v , couldn't enable uprobe %s", err, p.EbpfFuncName))
	}
	opts := &link.UprobeOptions{
		Offset: p.UprobeOffset,
		PID:    p.AttachPID,
	}

	var kp link.Link
	if isRet {
		kp, err = ex.Uretprobe(p.funcName, p.program, opts)
	} else {
		kp, err = ex.Uprobe(p.funcName, p.program, opts)
	}
	if err != nil {
		return fmt.Errorf("opening uprobe: %s , isRet:%t", err, isRet)
	}
	p.link = kp
	return nil
}

// attachCGroup - Attaches the probe to a cgroup hook point
func (p *Probe) attachCGroup() error {

	opts := link.CgroupOptions{
		Path:    p.CGroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: p.program,
	}
	kp, err := link.AttachCgroup(opts)
	if err != nil {
		return errors.New(fmt.Sprintf("error:%v , failed to attach probe %v to cgroup %s", err, p.GetIdentificationPair(), p.CGroupPath))
	}

	p.link = kp
	return nil
}

// attachSocket - Attaches the probe to the provided socket
func (p *Probe) attachSocket() error {
	return sockAttach(p.SocketFD, p.program.FD())
}

// detachSocket - Detaches the probe from its socket
func (p *Probe) detachSocket() error {
	return sockDetach(p.SocketFD, p.program.FD())
}

func (p *Probe) buildTCClsActQdisc() netlink.Qdisc {
	if p.tcClsActQdisc == nil {
		p.tcClsActQdisc = &netlink.GenericQdisc{
			QdiscType: "clsact",
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: int(p.Ifindex),
				Handle:    netlink.MakeHandle(0xffff, 0),
				Parent:    netlink.HANDLE_INGRESS,
			},
		}
	}
	return p.tcClsActQdisc
}
func (p *Probe) getTCFilterParentHandle() uint32 {
	return netlink.MakeHandle(clsactQdisc, uint16(p.NetworkDirection))
}
func (p *Probe) buildTCFilter() (netlink.BpfFilter, error) {
	if p.tcFilter.FilterAttrs.LinkIndex == 0 {
		var filterName string
		filterName, err := generateTCFilterName(p.UID, p.programSpec.SectionName, p.attachPID)
		if err != nil {
			return p.tcFilter, fmt.Errorf("couldn't create TC filter for %v: %w", p.EbpfFuncName, err)
		}
		p.tcFilter = netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: int(p.Ifindex),
				Parent:    p.getTCFilterParentHandle(),
				Handle:    p.TCFilterHandle,
				Priority:  p.TCFilterPrio,
				Protocol:  p.TCFilterProtocol,
			},
			Fd:           p.program.FD(),
			Name:         filterName,
			DirectAction: true,
		}
	}
	return p.tcFilter, nil
}

// attachTCCLS - Attaches the probe to its TC classifier hook point
func (p *Probe) attachTCCLS() error {
	var err error
	// Make sure Ifindex is properly set
	if p.Ifindex == 0 && p.Ifname == "" {
		return ErrInterfaceNotSet
	}

	// Recover the netlink socket of the interface from the manager
	ntl, ok := p.manager.netlinkCache[netlinkCacheKey{p.Ifindex, p.IfindexNetns}]
	if !ok {
		// Set up new netlink connection
		ntl, err = p.manager.newNetlinkConnection(p.Ifindex, p.IfindexNetns)
		if err != nil {
			return err
		}
	}

	// Create a Qdisc for the provided interface
	qdisc := &tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(p.Ifindex),
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  tc.HandleIngress,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}

	// Add the Qdisc
	err = ntl.rtNetlink.Qdisc().Add(qdisc)
	if err != nil {
		if err.Error() != "netlink receive: file exists" {
			return errors.New(fmt.Sprintf("error:%v , couldn't add a \", err clsact\" qdisc to interface %v", err, p.Ifindex))
		}
	}

	// Create qdisc filter
	fd := uint32(p.program.FD())
	flag := uint32(1)
	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(p.Ifindex),
			Handle:  0,
			Parent:  core.BuildHandle(tc.HandleRoot, uint32(p.NetworkDirection)),
			Info:    0x300,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fd,
				Name:  &p.Section,
				Flags: &flag,
			},
		},
	}

	// Add qdisc filter
	err = ntl.rtNetlink.Filter().Add(&filter)
	if err == nil {
		p.tcObject = qdisc
		ntl.schedClsCount += 1
		return nil
	}
	return errors.New(fmt.Sprintf("error:%v , couldn't add a %v filter to interface %v: %v", err, p.NetworkDirection, p.Ifindex, err))
}

// detachTCCLS - Detaches the probe from its TC classifier hook point
func (p *Probe) detachTCCLS() error {
	// Recover the netlink socket of the interface from the manager
	ntl, ok := p.manager.netlinkCache[netlinkCacheKey{p.Ifindex, p.IfindexNetns}]
	if !ok {
		return fmt.Errorf("couldn't find qdisc from which the probe %v was meant to be detached", p.GetIdentificationPair())
	}

	if ntl.schedClsCount >= 2 {
		ntl.schedClsCount -= 1
		// another classifier is still using the qdisc, do not delete it yet
		return nil
	}

	// Delete qdisc
	err := ntl.rtNetlink.Qdisc().Delete(p.tcObject)
	if err == nil {
		return nil
	}
	return errors.New(fmt.Sprintf("error:%v , couldn't detach TC classifier of probe %v", err, p.GetIdentificationPair()))
}

// attachXDP - Attaches the probe to an interface with an XDP hook point
func (p *Probe) attachXDP() error {
	// Lookup interface
	nlink, err := netlink.LinkByIndex(int(p.Ifindex))
	if err != nil {
		return errors.New(fmt.Sprintf("error:%v , couldn't retrieve interface %v", err, p.Ifindex))
	}

	// Attach program
	err = netlink.LinkSetXdpFdWithFlags(nlink, p.program.FD(), int(p.XDPAttachMode))
	if err == nil {
		return nil
	}
	return errors.New(fmt.Sprintf("error:%v , couldn't attach XDP program %v to interface %v", err, p.GetIdentificationPair(), p.Ifindex))
}

// detachXDP - Detaches the probe from its XDP hook point
func (p *Probe) detachXDP() error {
	// Lookup interface
	nlink, err := netlink.LinkByIndex(int(p.Ifindex))
	if err != nil {
		return errors.New(fmt.Sprintf("error:%v , couldn't retrieve interface %v", err, p.Ifindex))
	}

	// Detach program
	err = netlink.LinkSetXdpFdWithFlags(nlink, -1, int(p.XDPAttachMode))
	if err == nil {
		return nil
	}
	return errors.New(fmt.Sprintf("error:%v , couldn't detach XDP program %v from interface %v", err, p.GetIdentificationPair(), p.Ifindex))
}

// attachRawTracepoint - Attaches the probe to its raw_tracepoint
func (p *Probe) attachRawTracepoint() error {
	name := strings.TrimLeft(p.Section, "raw_tracepoint/")
	link, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    name,
		Program: p.program,
	})
	if err != nil {
		return errors.New(fmt.Sprintf("error:%v , couldn's activate raw_tracepoint %s, matchFuncName:%s", err, p.Section, p.EbpfFuncName))
	}
	p.link = link
	return nil
}
