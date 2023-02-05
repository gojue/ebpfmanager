package main

import (
	"github.com/gojue/ebpfmanager"
	"github.com/sirupsen/logrus"
)

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			Section:          "classifier/egress",
			EbpfFuncName:     "egress_cls_func",
			Ifname:           "eth0", // change this to the interface connected to the internet
			NetworkDirection: manager.Egress,
			SkipLoopback:     true,
		},
		{
			Section:          "classifier/ingress",
			EbpfFuncName:     "ingress_cls_func",
			Ifname:           "eth0", // change this to the interface connected to the internet
			NetworkDirection: manager.Ingress,
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
