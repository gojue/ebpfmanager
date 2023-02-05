package main

import (
	"github.com/sirupsen/logrus"

	"github.com/gojue/ebpfmanager"
)

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			Section:       "xdp/ingress",
			EbpfFuncName:  "egress_cls_func",
			Ifindex:       2, // change this to the interface index connected to the internet
			XDPAttachMode: manager.XdpAttachModeSkb,
		},
	},
}

func main() {
	// Initialize the manager
	if err := m.Init(recoverAssets()); err != nil {
		logrus.Fatal(err)
	}

	// Start the manager
	if err := m.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	// Generate some network traffic to trigger the probe
	trigger()

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
}
