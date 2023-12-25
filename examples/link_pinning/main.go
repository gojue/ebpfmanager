package main

import (
	"flag"
	"github.com/sirupsen/logrus"

	manager "github.com/gojue/ebpfmanager"
)

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			Section:      "raw_tracepoint/sys_enter",
			EbpfFuncName: "raw_tracepoint_sys_enter",
			LinkPinPath:  "/sys/fs/bpf/sys_enter_link",
		},
	},
}

func main() {
	// Parse CLI arguments
	var kill bool
	flag.BoolVar(&kill, "kill", false, "kills the programs suddenly before doing any cleanup")
	flag.Parse()

	logrus.Println("if User-Space application exits, pinned link programs will still run")

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
		logrus.Println("=> Stopping the program without cleanup, the pinned link should show up in /sys/fs/bpf/")
		logrus.Println("=> You can check the logs /sys/kernel/debug/tracing/trace_pipe")
		return
	}

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
}
