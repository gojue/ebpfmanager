package main

import (
	"bufio"
	"errors"
	"github.com/gojue/ebpfmanager"
	"github.com/sirupsen/logrus"
	"os"
	"strings"
	"time"
)

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			EbpfFuncName: "bpf_sockops",
			Section:      "sockops",
		},
	},
}

func main() {
	cp, err := detectCgroupPath()
	if err != nil {
		logrus.Fatal(err)
	}
	m.Probes[0].CGroupPath = cp

	logrus.Println("try to attach sockops ebpf programs.")
	// Initialize the manager
	if err := m.Init(recoverAssets()); err != nil {
		logrus.Fatal(err)
	}

	// Start the manager
	if err := m.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")
	time.Sleep(time.Second * 3)
	// Generate some network traffic to trigger the probe
	trigger()

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
}

func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 is not mounted")
}
