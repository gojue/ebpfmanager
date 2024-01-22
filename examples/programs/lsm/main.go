package main

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/gojue/ebpfmanager/kernel"
	"os"
	"os/signal"
	"runtime"
	"time"

	manager "github.com/gojue/ebpfmanager"
	"github.com/sirupsen/logrus"
)

var m = &manager.Manager{
	Probes: []*manager.Probe{
		&manager.Probe{
			UID:              "MyLSMPathMkdirHook",
			Section:          "lsm/path_mkdir",
			EbpfFuncName:     "lsm_path_mkdir",
			AttachToFuncName: "path_mkdir",
		},
	},
}

func main() {
	if features.HaveProgramType(ebpf.LSM) != nil {
		return
	}
	lvc, err := features.LinuxVersionCode()
	if err != nil {
		return
	}
	//Check whether the arch arm64/aarch64 environment kernel version >= 6
	if runtime.GOARCH == "arm64" && (lvc>>16) < 6 {
		// LSM unsupported
		return
	}

	// Linux kernel version >= 5.7
	logrus.Println("initializing manager")
	kv, err := kernel.HostVersion()
	if err != nil {
		// nothing to do.
	}
	if kv < kernel.VersionCode(5, 7, 0) {
		logrus.Println(manager.ErrLSMNotSupported, "current kernel version is:", kv.String())
		return
	}

	// Run the cat /boot/config-$(uname -r) | grep BPF_LSM command to check whether the LSM is supported
	// check CONFIG_BPF_LSM=y
	logrus.Println("cat /boot/config-$(uname -r) | grep BPF_LSM")
	isSupportLSM := checkSupportLSM()
	if !isSupportLSM {
		logrus.Println(manager.ErrLSMNotSupported, "Linux kernel does not support CONFIG_BPF_LSM=y")
		return
	} else {
		logrus.Println("Linux kernel supports CONFIG_BPF_LSM=y")
	}

	options := manager.Options{
		DefaultProbeRetry:      2,
		DefaultProbeRetryDelay: time.Second,
	}

	// Initialize the manager
	if err := m.InitWithOptions(recoverAssets(), options); err != nil {
		logrus.Fatal(err)
	}

	// Start the manager
	if err := m.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("successfully started")
	logrus.Println("=> head over to /sys/kernel/debug/tracing/trace_pipe")
	logrus.Println("=> checkout /sys/kernel/debug/tracing/kprobe_events, utimes_common might have become utimes_common.isra.0")
	logrus.Println("=> Cmd+C to exit")

	// Create a folder to trigger the probes
	if err := trigger(); err != nil {
		logrus.Error(err)
	}

	wait()

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
}

// wait - Waits until an interrupt or kill signal is sent
func wait() {
	logrus.Println("run next testcase after 3 second")
	time.Sleep(time.Second * 3)
	return
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}
