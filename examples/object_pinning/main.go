package main

import (
	"flag"
	"github.com/gojue/ebpfmanager"
	"github.com/sirupsen/logrus"
)

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			Section:          "kprobe/mkdirat",
			PinPath:          "/sys/fs/bpf/mkdirat",
			AttachToFuncName: "mkdirat",
			EbpfFuncName:     "kprobe_mkdirat",
		},
		{
			Section:          "kretprobe/mkdirat",
			AttachToFuncName: "mkdirat",
			EbpfFuncName:     "kretprobe_mkdirat",
		},
		{
			Section:          "kprobe/mkdir",
			PinPath:          "/sys/fs/bpf/mkdir",
			AttachToFuncName: "mkdir",
			EbpfFuncName:     "kprobe_mkdir",
		},
		{
			Section:          "kretprobe/mkdir",
			AttachToFuncName: "mkdir",
			EbpfFuncName:     "kretprobe_mkdir",
		},
	},
	Maps: []*manager.Map{
		{
			Name: "map1",
			MapOptions: manager.MapOptions{
				PinPath: "/sys/fs/bpf/map1",
			},
		},
	},
}

func main() {
	// Parse CLI arguments
	var kill bool
	flag.BoolVar(&kill, "kill", false, "kills the programs suddenly before doing any cleanup")
	flag.Parse()

	logrus.Println("if they exist, pinned object will be automatically loaded")

	// Initialize the manager
	if err := m.Init(recoverAssets()); err != nil {
		logrus.Fatal(err)
	}

	// Start the manager
	if err := m.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	// Create a folder to trigger the probes
	if err := trigger(); err != nil {
		logrus.Error(err)
	}

	if kill {
		logrus.Println("=> Stopping the program without cleanup, the pinned map and programs should show up in /sys/fs/bpf/")
		logrus.Println("=> Restart without --kill to load the pinned object from the bpf file system and properly remove them")
		return
	}

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
}
