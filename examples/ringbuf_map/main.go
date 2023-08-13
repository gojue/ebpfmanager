package main

import (
	_ "embed"
	manager "github.com/gojue/ebpfmanager"
	"github.com/gojue/ebpfmanager/kernel"
	"github.com/sirupsen/logrus"
)

var m = &manager.Manager{
	Probes: []*manager.Probe{
		&manager.Probe{
			UID:              "MyFirstHook",
			Section:          "kprobe/vfs_mkdir",
			AttachToFuncName: "vfs_mkdir",
			EbpfFuncName:     "kprobe_vfs_mkdir",
		},
	},
	RingbufMaps: []*manager.RingbufMap{
		&manager.RingbufMap{
			Map: manager.Map{
				Name: "ringbuf_map",
			},
			RingbufMapOptions: manager.RingbufMapOptions{
				DataHandler: myDataHandler,
			},
		},
	},
}

// myDataHandler - Perf event data handler
func myDataHandler(cpu int, data []byte, ringbufmap *manager.RingbufMap, manager *manager.Manager) {
	pid := ByteOrder.Uint32(data[0:4])
	flag := ByteOrder.Uint32(data[4:8])
	logrus.Printf("received: CPU:%d pid:%d,flag:%d", cpu, pid, flag)
}

func main() {
	//Initialize the manager
	logrus.Println("initializing manager")
	kv, err := kernel.HostVersion()
	if err != nil {
		// nothing to do.
	}
	if kv < kernel.VersionCode(5, 8, 0) {
		logrus.Println(manager.ErrRingbufNotSupported, "current kernel version is:", kv.String())
		return
	}
	if err := m.Init(recoverAssets()); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")
	// Start the manager
	if err := m.Start(); err != nil {
		logrus.Fatal(err)
	}

	// Create a folder to trigger the probes
	if err := trigger(); err != nil {
		logrus.Error(err)
	}

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}

}
