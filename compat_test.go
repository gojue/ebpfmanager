package manager

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

func compatibilitySpec(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()
	spec, err := ebpf.LoadCollectionSpec("testdata/compat.elf")
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func TestLegacyAutomaticConstants(t *testing.T) {
	spec := compatibilitySpec(t)
	spec.Programs["asm_constant"] = &ebpf.ProgramSpec{Type: ebpf.SocketFilter, Instructions: asm.Instructions{
		asm.LoadImm(asm.R0, 0, asm.DWord).WithReference("asm_value"), asm.Return(),
	}}
	m := &Manager{collectionSpec: spec, state: initialized, options: Options{ConstantEditors: []ConstantEditor{
		{Name: "target_pid", Value: uint64(41), FailOnMissing: true},
		{Name: "target_uid", Value: uint64(42), FailOnMissing: true},
		{Name: "asm_value", Value: uint64(43)},
	}}}
	if err := m.editConstants(); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]uint64{"target_pid": 41, "target_uid": 42} {
		var got uint64
		if err := spec.Variables[name].Get(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%s = %d, want %d", name, got, want)
		}
	}
	if got := spec.Programs["asm_constant"].Instructions[0].Constant; got != 43 {
		t.Fatalf("ASM constant = %d", got)
	}
	m.options.ConstantEditors = []ConstantEditor{{Name: "missing", Value: uint64(1), BTFGlobalConstant: true, FailOnMissing: true}}
	if err := m.editConstants(); err == nil {
		t.Fatal("missing required BTF constant accepted")
	}
	m.options.ConstantEditors[0].FailOnMissing = false
	if err := m.editConstants(); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidConstantInstruction(t *testing.T) {
	spec := &ebpf.ProgramSpec{Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0).WithReference("bad"), asm.Return()}}
	if err := (&Manager{}).editConstant(spec, ConstantEditor{Name: "bad", Value: uint64(1)}); err == nil {
		t.Fatal("malformed constant instruction silently accepted")
	}
}

func TestProbeCopyAttachmentSettings(t *testing.T) {
	original := &Probe{}
	v := reflect.ValueOf(original).Elem()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if !field.CanSet() {
			continue
		}
		switch field.Kind() {
		case reflect.String:
			field.SetString(v.Type().Field(i).Name)
		case reflect.Bool:
			field.SetBool(true)
		case reflect.Int, reflect.Int32, reflect.Int64:
			field.SetInt(7)
		case reflect.Uint, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			field.SetUint(9)
		}
	}
	copied := reflect.ValueOf(original.Copy()).Elem()
	for i := 0; i < v.NumField(); i++ {
		if v.Type().Field(i).IsExported() && !reflect.DeepEqual(v.Field(i).Interface(), copied.Field(i).Interface()) {
			t.Errorf("Copy lost %s", v.Type().Field(i).Name)
		}
	}
}

func TestLegacyUprobeRelativeOffset(t *testing.T) {
	p := &Probe{UAddress: 0x1234, UprobeOffset: 16, HookFuncName: "not_a_symbol", BinaryPath: "not_a_file"}
	for range 2 {
		got, err := p.resolveUprobeOffset()
		if err != nil {
			t.Fatal(err)
		}
		if got != 0x1244 || p.UprobeOffset != 16 || p.UAddress != 0x1234 {
			t.Fatalf("changed address/offset: %#v, %x", p, got)
		}
	}
	p.UAddress = ^uint64(0)
	if _, err := p.resolveUprobeOffset(); err == nil {
		t.Fatal("offset overflow accepted")
	}
}

func TestLegacyInterfaceAndPID(t *testing.T) {
	p := &Probe{Ifindex: 12, Ifname: "eth-test", AttachPID: 42}
	if err := p.normalizeLegacyFields(); err != nil {
		t.Fatal(err)
	}
	if p.IfIndex != 12 || p.IfName != "eth-test" || p.PerfEventPID != 42 {
		t.Fatalf("legacy fields not applied: %#v", p)
	}
}

func TestLegacyFunctionExclusion(t *testing.T) {
	m := &Manager{Probes: []*Probe{{UID: "ecapture", EbpfFuncName: "access_map_one", Section: "socket"}}}
	f, err := os.Open("testdata/exclude.elf")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := m.initState(f, Options{ExcludedEbpfFuncs: []string{"access_map_one"}}); err != nil {
		t.Fatal(err)
	}
	if len(m.Probes) != 0 || m.collectionSpec.Programs["access_map_one"] != nil {
		t.Fatal("legacy excluded function retained")
	}
}

func TestSyscallExactSymbolAndWhitespace(t *testing.T) {
	path := t.TempDir() + "/kallsyms"
	if err := os.WriteFile(path, []byte("000 T tcp_sendmsg\n000\tT\tsys_open\n000 T sys_exit\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for input, want := range map[string]string{"tcp_sendmsg": "tcp_sendmsg", "sys_exit": "sys_exit", "open": "sys_open"} {
		got, err := GetSyscallFnNameWithSymFile(input, path)
		if err != nil || got != want {
			t.Fatalf("%s: got %s, %v; want %s", input, got, err, want)
		}
	}
}

//go:noinline
func compatibilityUprobeTarget(value int) int { return value + 1 }

func TestLegacyUAddressAttach(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Go may strip the temporary test binary's symbol table. Resolve the
	// executable file offset from the process mapping, as eCapture does for
	// stripped Go binaries, instead of requiring an ELF symbol.
	pc := uint64(reflect.ValueOf(compatibilityUprobeTarget).Pointer())
	mappings, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatal(err)
	}
	var address uint64
	for _, line := range strings.Split(string(mappings), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		var start, end uint64
		if _, err := fmt.Sscanf(fields[0], "%x-%x", &start, &end); err != nil {
			continue
		}
		if pc >= start && pc < end {
			offset, err := strconv.ParseUint(fields[2], 16, 64)
			if err != nil {
				t.Fatal(err)
			}
			address = pc - start + offset
			break
		}
	}
	if address == 0 {
		t.Fatal("test function is not mapped")
	}

	for _, method := range []AttachMethod{AttachWithPerfEventOpen, AttachWithProbeEvents} {
		t.Run(map[AttachMethod]string{AttachWithPerfEventOpen: "pmu", AttachWithProbeEvents: "tracefs"}[method], func(t *testing.T) {
			m := &Manager{Probes: []*Probe{{UID: "compat_uprobe", Section: "uprobe/compat", EbpfFuncName: "compat_uprobe",
				AttachToFuncName: "not_in_symbol_table", BinaryPath: exe, UAddress: address, AttachPID: os.Getpid(), UprobeAttachMethod: method}}, Maps: []*Map{{Name: "hits"}}}
			f, err := os.Open("testdata/compat.elf")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err := m.InitWithOptions(f, Options{RemoveRlimit: true}); err != nil {
				t.Fatal(err)
			}
			defer m.Stop(CleanAll)
			if err := m.Start(); err != nil {
				t.Fatal(err)
			}
			if compatibilityUprobeTarget(1) != 2 {
				t.Fatal("target failed")
			}
			mp, found, err := m.GetMap("hits")
			if err != nil || !found {
				t.Fatalf("hits map: %v", err)
			}
			var hits uint64
			if err := mp.Lookup(uint32(0), &hits); err != nil {
				t.Fatal(err)
			}
			if hits == 0 {
				t.Fatal("address-only uprobe did not fire")
			}
		})
	}
}

func TestVerifierErrorWrappingCompatibility(t *testing.T) {
	sentinel := errors.New("verifier cause")
	wrapped := ConcatErrors(sentinel, errors.New("cleanup"))
	if !errors.Is(wrapped, sentinel) || !strings.Contains(wrapped.Error(), "cleanup") {
		t.Fatal(wrapped)
	}
}

func TestLegacyInnerMapEditor(t *testing.T) {
	inner := &ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1}
	m := &Manager{state: initialized, collectionSpec: &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		"outer": {Name: "outer", Type: ebpf.ArrayOfMaps, KeySize: 4, ValueSize: 4, MaxEntries: 1},
	}}, options: Options{MapSpecEditors: map[string]MapSpecEditor{"outer": {EditorFlag: EditInnerMap, InnerMap: inner}}}}
	if EditInnerMap != 1<<4 {
		t.Fatal("legacy editor flag changed")
	}
	if err := m.editMapSpecs(); err != nil {
		t.Fatal(err)
	}
	if m.collectionSpec.Maps["outer"].InnerMap != inner {
		t.Fatal("inner map editor not applied")
	}
}

func TestLegacyRingbufCallbackDuringStop(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	callbackErr := make(chan error, 1)
	rb := &RingbufMap{Map: Map{Name: "events"}, RingbufMapOptions: RingbufMapOptions{
		DataHandler: func(_ int, _ []byte, _ *RingbufMap, m *Manager) {
			close(entered)
			<-release
			_, _, err := m.GetMap("events")
			callbackErr <- err
		},
	}}
	m := &Manager{RingbufMaps: []*RingbufMap{rb}, state: elfLoaded, collectionSpec: &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{"events": {Name: "events", Type: ebpf.RingBuf, MaxEntries: uint32(os.Getpagesize())}},
	}}
	if err := m.InitWithOptions(nil, Options{RemoveRlimit: true}); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.SocketFilter, License: "MIT", Instructions: asm.Instructions{
		asm.Mov.Imm(asm.R0, 42), asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.LoadMapPtr(asm.R1, rb.array.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8),
		asm.Mov.Imm(asm.R3, 8), asm.Mov.Imm(asm.R4, 0), asm.FnRingbufOutput.Call(),
		asm.Mov.Imm(asm.R0, 0), asm.Return(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer program.Close()
	if _, _, err := program.Test(make([]byte, 14)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("ring buffer callback not invoked")
	}
	// Take the same lock as Stop, deterministically forcing the callback to
	// contend with shutdown. stop must drop the lock while joining readers.
	m.stateLock.Lock()
	stopped := make(chan error, 1)
	go func() { err := m.stop(CleanAll); m.stateLock.Unlock(); stopped <- err }()
	close(release)
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown deadlocked with callback")
	}
	if err := <-callbackErr; err != nil {
		t.Fatal(err)
	}
	if rb.array != nil {
		t.Fatal("ring buffer map was not cleaned up")
	}
}

func TestMapReplacementKeepsCallerFD(t *testing.T) {
	spec := &ebpf.MapSpec{Name: "shared", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1}
	original, err := ebpf.NewMap(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	m := &Manager{Maps: []*Map{{Name: "shared"}}, state: elfLoaded, collectionSpec: &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{"shared": spec}}}
	if err := m.InitWithOptions(nil, Options{MapEditors: map[string]*ebpf.Map{"shared": original}}); err != nil {
		t.Fatal(err)
	}
	owned, _, err := m.GetMap("shared")
	if err != nil {
		t.Fatal(err)
	}
	if owned.FD() == original.FD() {
		t.Fatal("replacement reused caller FD")
	}
	if err := m.Stop(CleanAll); err != nil {
		t.Fatal(err)
	}
	if err := original.Put(uint32(0), uint64(42)); err != nil {
		t.Fatalf("caller map was closed: %v", err)
	}
}

func TestPinnedLinkReuseAndReattach(t *testing.T) {
	var fs unix.Statfs_t
	if err := unix.Statfs("/sys/fs/bpf", &fs); err != nil || fs.Type != unix.BPF_FS_MAGIC {
		t.Skip("bpffs is not mounted")
	}
	dir, err := os.MkdirTemp("/sys/fs/bpf", "ebpfmanager-compat-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	pin := dir + "/link"
	newManager := func() *Manager {
		return &Manager{state: elfLoaded, Probes: []*Probe{{UID: "pin_compat", EbpfFuncName: "raw", Section: "raw_tracepoint/sys_enter", LinkPinPath: pin}},
			collectionSpec: &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{"raw": {
				Name: "raw", Type: ebpf.RawTracepoint, SectionName: "raw_tracepoint/sys_enter", License: "MIT", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
			}}},
		}
	}
	first := newManager()
	if err := first.InitWithOptions(nil, Options{RemoveRlimit: true}); err != nil {
		t.Fatal(err)
	}
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	originalID := first.Probes[0].ID()
	// Closing descriptors without unpinning simulates a previous owner exiting.
	if err := first.Probes[0].progLink.Close(); err != nil {
		t.Fatal(err)
	}
	first.Probes[0].progLink = nil
	if err := first.Stop(CleanAll); err != nil {
		t.Fatal(err)
	}
	second := newManager()
	if err := second.InitWithOptions(nil, Options{RemoveRlimit: true}); err != nil {
		t.Fatal(err)
	}
	defer second.Stop(CleanAll)
	if err := second.Start(); err != nil {
		t.Fatal(err)
	}
	if second.Probes[0].ID() != originalID {
		t.Fatal("reused link exposes an unrelated new program")
	}
	if err := second.Probes[0].Detach(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pin); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("detached link still pinned: %v", err)
	}
	if err := second.Probes[0].Attach(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pin); err != nil {
		t.Fatalf("reattached link not pinned: %v", err)
	}
}

func TestPinnedMapAndProgramReuse(t *testing.T) {
	var fs unix.Statfs_t
	if err := unix.Statfs("/sys/fs/bpf", &fs); err != nil || fs.Type != unix.BPF_FS_MAGIC {
		t.Skip("bpffs is not mounted")
	}
	dir, err := os.MkdirTemp("/sys/fs/bpf", "ebpfmanager-objects-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	newManager := func() *Manager {
		return &Manager{state: elfLoaded,
			Maps:   []*Map{{Name: "shared", MapOptions: MapOptions{PinPath: dir + "/map"}}},
			Probes: []*Probe{{UID: "objects_compat", EbpfFuncName: "raw", Section: "raw_tracepoint/sys_enter", PinPath: dir + "/program"}},
			collectionSpec: &ebpf.CollectionSpec{
				Maps:     map[string]*ebpf.MapSpec{"shared": {Name: "shared", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1}},
				Programs: map[string]*ebpf.ProgramSpec{"raw": {Name: "raw", Type: ebpf.RawTracepoint, SectionName: "raw_tracepoint/sys_enter", License: "MIT", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}}},
			},
		}
	}
	first := newManager()
	if err := first.InitWithOptions(nil, Options{RemoveRlimit: true}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"map", "program"} {
		if _, err := os.Stat(dir + "/" + name); err != nil {
			t.Fatalf("%s not pinned: %v", name, err)
		}
	}
	originalID := first.Probes[0].ID()
	firstMap, _, _ := first.GetMap("shared")
	if err := firstMap.Put(uint32(0), uint64(42)); err != nil {
		t.Fatal(err)
	}
	// Release descriptors while retaining both pins, as after owner exit.
	first.collection.Close()
	second := newManager()
	if err := second.InitWithOptions(nil, Options{RemoveRlimit: true}); err != nil {
		t.Fatal(err)
	}
	defer second.Stop(CleanAll)
	if second.Probes[0].ID() != originalID {
		t.Fatal("pinned program was replaced")
	}
	maps, err := second.GetMaps()
	if err != nil {
		t.Fatal(err)
	}
	var got uint64
	if err := maps["shared"].Lookup(uint32(0), &got); err != nil || got != 42 {
		t.Fatalf("pinned map contents: %d, %v", got, err)
	}
	programs, err := second.GetPrograms()
	if err != nil {
		t.Fatal(err)
	}
	if programs["raw"] != second.Probes[0].Program() {
		t.Fatal("collection omitted pinned program")
	}
	if err := second.Start(); err != nil {
		t.Fatal(err)
	}
	if err := second.Stop(CleanAll); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"map", "program"} {
		if _, err := os.Stat(dir + "/" + name); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s not cleaned: %v", name, err)
		}
	}
}
