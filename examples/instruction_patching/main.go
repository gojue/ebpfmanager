package main

import (
	_ "embed"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/sirupsen/logrus"
	"log"
	"time"

	manager "github.com/gojue/ebpfmanager"
)

var Probe []byte

const eBPFFuncName = "kprobe__security_socket_create"
const eBPFAsmValue = 255

var m1 = &manager.Manager{
	Probes: []*manager.Probe{
		{
			UID:              "MyFirstHook",
			Section:          "kprobe/vfs_mkdir",
			AttachToFuncName: "vfs_mkdir",
			EbpfFuncName:     eBPFFuncName,
		},
	},
	InstructionPatchers: []manager.InstructionPatcherFunc{patchBPFTelemetry},
}

const BPFTelemetryPatchCall = -1

func getAllProgramSpecs(m *manager.Manager) ([]*ebpf.ProgramSpec, error) {
	var specs []*ebpf.ProgramSpec
	for _, p := range m.Probes {
		oldID := manager.ProbeIdentificationPair{p.UID, p.EbpfFuncName}
		s, present, err := m.GetProgramSpec(oldID)
		if err != nil {
			return nil, err
		}
		if !present {
			return nil, fmt.Errorf("could not find ProgramSpec for probe %v", oldID)
		}

		specs = append(specs, s...)
	}

	return specs, nil
}

func patchBPFTelemetry(m *manager.Manager) error {
	specs, err := getAllProgramSpecs(m)
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

			if ins.Constant != BPFTelemetryPatchCall {
				continue
			}
			*ins = asm.Mov.Imm(asm.R1, int32(eBPFAsmValue)).WithMetadata(ins.Metadata)
		}
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if err := m1.Init(recoverAssets()); err != nil {
		return err
	}
	defer func() {
		if err := m1.Stop(manager.CleanAll); err != nil {
			log.Print(err)
		}
	}()

	if err := m1.Start(); err != nil {
		return err
	}

	log.Println("=> Use 'bpftool prog dump xlated id <prog-id>' to verify that the instruction has been patched")
	log.Println("=> Enter to exit")
	// check output with `bpftool prog dump xlated id <prog-id>`
	/*
		root@vm-ubuntu-arm64:/home/cfc4n# bpftool prog dump xlated id 664
		   0: (b7) r1 = 0
		   1: (b7) r1 = 255
		   2: (b7) r0 = 1
		   3: (95) exit
	*/
	// wait for eBPF program to be loaded
	time.Sleep(time.Second * 3)

	err := check(eBPFFuncName)

	if err != nil {
		logrus.Errorf("failed to check eBPF program: %v", err)
	}
	if err = m1.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
	log.Println("=> Stopped the manager")
	return nil
}
