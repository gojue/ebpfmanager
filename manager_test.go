package manager

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"
)

func TestVerifierError(t *testing.T) {
	err := rlimit.RemoveMemlock()
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		collectionSpec: &ebpf.CollectionSpec{
			Programs: map[string]*ebpf.ProgramSpec{"socket__filter": {
				Type: ebpf.SocketFilter,
				Instructions: asm.Instructions{
					asm.LoadImm(asm.R0, 0, asm.DWord),
					// Missing Return
				},
				License: "MIT",
			}},
		},
	}
	err = m.loadCollection()
	if err == nil {
		t.Fatal("expected error")
	}
	var ve *ebpf.VerifierError
	if !errors.As(err, &ve) {
		t.Fatal("expected to be able to unwrap to VerifierError")
	}
	if strings.Count(err.Error(), "\n") == 0 {
		t.Fatal("expected full verifier error")
	}
}

func TestExclude(t *testing.T) {
	err := rlimit.RemoveMemlock()
	if err != nil {
		t.Fatal(err)
	}

	m := &Manager{
		Probes: []*Probe{
			{EbpfFuncName: "access_map_one"},
		},
		Maps: []*Map{
			{Name: "map_one"},
		},
	}
	opts := Options{
		RemoveRlimit: true,
		ExcludedMaps: []string{"map_two"},
	}

	f, err := os.Open("testdata/exclude.elf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	err = m.InitWithOptions(f, opts)
	if err == nil || !strings.Contains(err.Error(), "missing map map_two") {
		t.Fatalf("expected error about missing map map_two, got `%s` instead", err)
	}

	opts.ExcludedFunctions = []string{"access_map_two"}
	err = m.InitWithOptions(f, opts)
	if err != nil {
		t.Fatal(err)
	}
}

func TestManager_getTracefsRegex(t *testing.T) {
	tests := []struct {
		name          string
		Probes        []*Probe
		expectedRegex string
	}{
		{
			name: "sanity",
			Probes: []*Probe{
				{
					UID: "HTTP",
				},
				{
					UID: "tcp",
				},
			},
			expectedRegex: "(p|r)[0-9]*:(kprobes|uprobes)\\/(.*(HTTP|tcp)*_([0-9]*)) .*",
		},
		{
			name: "duplications",
			Probes: []*Probe{
				{
					UID: "HTTP",
				},
				{
					UID: "HTTP",
				},
			},
			expectedRegex: "(p|r)[0-9]*:(kprobes|uprobes)\\/(.*(HTTP)*_([0-9]*)) .*",
		},
		{
			name: "special character",
			Probes: []*Probe{
				{
					UID: "+++++",
				},
				{
					UID: "+3.*.*",
				},
			},
			expectedRegex: "(p|r)[0-9]*:(kprobes|uprobes)\\/(.*(\\+\\+\\+\\+\\+|\\+3\\.\\*\\.\\*)*_([0-9]*)) .*",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manager{
				Probes: tt.Probes,
			}
			res, err := m.getTracefsRegex()
			if err != nil {
				t.Fatal(err)
			}
			if res.String() != tt.expectedRegex {
				t.Fatalf("expected: %s, got: %s", tt.expectedRegex, res.String())
			}
		})
	}
}

func TestDumpMaps(t *testing.T) {
	err := rlimit.RemoveMemlock()
	if err != nil {
		t.Fatal(err)
	}

	m := &Manager{
		Probes: []*Probe{
			{EbpfFuncName: "access_map_one"},
		},
		Maps: []*Map{
			{Name: "map_one"},
		},
	}

	opts := Options{
		ExcludedFunctions: []string{"access_map_two"},
	}

	f, err := os.Open("testdata/exclude.elf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })

	err = m.InitWithOptions(f, opts)
	if err != nil {
		t.Fatal(err)
	}

	dumpContents := "mapdump"

	m.DumpHandler = func(w io.Writer, _ *Manager, mapName string, currentMap *ebpf.Map) {
		_, _ = io.WriteString(w, dumpContents)
	}

	var output bytes.Buffer
	err = m.DumpMapsTo(&output, "map_one")
	if err != nil {
		t.Fatal(err)
	}

	if dumpContents != output.String() {
		t.Errorf("expected %s, got %s", dumpContents, output.String())
	}
}

func TestInstructionPatching(t *testing.T) {
	err := rlimit.RemoveMemlock()
	if err != nil {
		t.Fatal(err)
	}

	// We want to test multiple patchers, so we'll use a generic one
	// and call it twice with different constants.
	// The patching.c program contains two invalid calls, with constants
	// -1 and -2. We just replace them with a movimm instruction.
	genericPatcher := func(m *Manager, constant int64) error {
		specs, err := m.GetProgramSpecs()
		if err != nil {
			return err
		}
		for _, spec := range specs {
			if spec == nil {
				continue
			}
			iter := spec.Instructions.Iterate()
			for iter.Next() {
				ins := iter.Ins

				if !ins.IsBuiltinCall() {
					continue
				}

				if ins.Constant == constant {
					*ins = asm.Mov.Imm(asm.R1, int32(0xff)).WithMetadata(ins.Metadata)
				}
			}
		}
		return nil
	}

	m := &Manager{
		Probes: []*Probe{
			{EbpfFuncName: "patching_test"},
		},
		InstructionPatchers: []InstructionPatcherFunc{
			func(m *Manager) error { return genericPatcher(m, -1) },
			func(m *Manager) error { return genericPatcher(m, -2) },
		},
	}

	f, err := os.Open("testdata/patching.elf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })

	// If any of the patchers fail, they will leave an invalid call instruction
	// in the program, which will cause the verifier to fail. This allows us
	// to not do any extra validation.
	err = m.InitWithOptions(f, Options{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLoadELF(t *testing.T) {
	f, err := os.Open("testdata/patching.elf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })

	m := &Manager{
		state: reset,
	}
	if err = m.LoadELF(f); err != nil {
		t.Errorf("LoadELF() error = %v, expected: %v", err, nil)
	}
	if err = m.LoadELF(f); !errors.Is(err, ErrManagerELFLoaded) {
		t.Errorf("LoadELF() error = %v, expected: %v", err, ErrManagerELFLoaded)
	}
}

func TestReleaseKernelBTF(t *testing.T) {
	// releaseKernelBTF (called by Start) must drop both the KernelTypes spec and the shared BTF
	// cache once loading is done, unless the caller opted into keeping them via KeepKernelBTF.
	// Otherwise a long-lived manager keeps the parsed kernel BTF (vmlinux) pinned for the whole
	// process lifetime, which regressed idle memory for a downstream consumer.
	tests := []struct {
		name          string
		keepKernelBTF bool
		wantCleared   bool
	}{
		{name: "released by default", keepKernelBTF: false, wantCleared: true},
		{name: "retained when KeepKernelBTF is set", keepKernelBTF: true, wantCleared: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manager{}
			m.options.KeepKernelBTF = tt.keepKernelBTF
			m.options.VerifierOptions.Programs.KernelTypes = &btf.Spec{}
			m.options.VerifierOptions.Cache = btf.NewCache()

			m.releaseKernelBTF()

			if cleared := m.options.VerifierOptions.Programs.KernelTypes == nil; cleared != tt.wantCleared {
				t.Errorf("KernelTypes cleared = %v, want %v", cleared, tt.wantCleared)
			}
			if cleared := m.options.VerifierOptions.Cache == nil; cleared != tt.wantCleared {
				t.Errorf("Cache cleared = %v, want %v", cleared, tt.wantCleared)
			}
		})
	}
}
