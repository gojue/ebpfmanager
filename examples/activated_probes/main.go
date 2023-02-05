package main

import (
	"fmt"
	"github.com/gojue/ebpfmanager"
	"os"
	"os/signal"
	"time"

	"github.com/sirupsen/logrus"
)

var m1 = &manager.Manager{
	Probes: []*manager.Probe{
		{
			UID:              "MyVFSMkdir1",
			Section:          "kprobe/vfs_mkdir",
			EbpfFuncName:     "kprobe_vfs_mkdir",
			AttachToFuncName: "vfs_mkdir",
		},
		{
			Section:          "kprobe/vfs_opennnnnn",
			EbpfFuncName:     "kprobe_open",
			AttachToFuncName: "open",
		},
		{
			Section:          "kprobe/exclude",
			EbpfFuncName:     "kprobe_exclude",
			AttachToFuncName: "exclude",
		},
	},
}

var options1 = manager.Options{
	ActivatedProbes: []manager.ProbesSelector{
		&manager.ProbeSelector{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          "MyVFSMkdir1",
				EbpfFuncName: "kprobe_vfs_mkdir",
			},
		},
		&manager.AllOf{
			Selectors: []manager.ProbesSelector{
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						UID:          "MyVFSMkdir1",
						EbpfFuncName: "kprobe_vfs_mkdir",
					},
				},
			},
		},
		&manager.OneOf{
			Selectors: []manager.ProbesSelector{
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EbpfFuncName: "kprobe_open",
					},
				},
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EbpfFuncName: "kprobe_exclude",
					},
				},
			},
		},
		&manager.BestEffort{
			Selectors: []manager.ProbesSelector{
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EbpfFuncName: "kprobe_open",
					},
				},
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EbpfFuncName: "kprobe_exclude",
					},
				},
			},
		}},
	ExcludedEbpfFuncs: []string{
		"kprobe_exclude",
	},
}

var m2 = &manager.Manager{
	Probes: []*manager.Probe{
		{
			UID:              "MyVFSMkdir2",
			Section:          "kprobe/vfs_mkdir",
			EbpfFuncName:     "kprobe_vfs_mkdir",
			AttachToFuncName: "vfs_mkdir",
		},
		{
			Section:          "kprobe/vfs_opennnnnn",
			EbpfFuncName:     "kprobe_open",
			AttachToFuncName: "open",
		},
		{
			Section:          "kprobe/exclude",
			EbpfFuncName:     "kprobe_exclude",
			AttachToFuncName: "exclude",
		},
	},
}

var options2 = manager.Options{
	ActivatedProbes: []manager.ProbesSelector{
		&manager.ProbeSelector{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          "MyVFSMkdir2",
				EbpfFuncName: "kprobe_vfs_mkdir",
			},
		},
		&manager.AllOf{
			Selectors: []manager.ProbesSelector{
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EbpfFuncName: "kprobe_open",
					},
				},
			},
		},
		&manager.OneOf{
			Selectors: []manager.ProbesSelector{
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EbpfFuncName: "kprobe_open",
					},
				},
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						EbpfFuncName: "kprobe_exclude",
					},
				},
			},
		},
	},
	ExcludedEbpfFuncs: []string{
		"kprobe_exclude",
	},
}

var m3 = &manager.Manager{
	Probes: []*manager.Probe{
		{
			UID:              "MyVFSMkdir2",
			Section:          "kprobe/vfs_mkdir",
			EbpfFuncName:     "kprobe_vfs_mkdir",
			AttachToFuncName: "vfs_mkdir",
		},
		{
			Section:          "kprobe/vfs_opennnnnn",
			EbpfFuncName:     "kprobe_open",
			AttachToFuncName: "open",
		},
		{
			Section:          "kprobe/exclude",
			EbpfFuncName:     "kprobe_exclude",
			AttachToFuncName: "ext4_fc_replay_check_excluded",
		},
	},
}

func main() {
	// Initialize the managers
	logrus.Printf("Kprobe/exclude2 start...")
	if err := m1.InitWithOptions(recoverAssets(), options1); err != nil {
		logrus.Fatal(err)
	}

	// Start m1
	logrus.Printf("m1.Start()...")
	if err := m1.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("m1 successfully started")

	// Create a folder to trigger the probes
	if err := trigger(); err != nil {
		logrus.Error(err)
	}

	if err := m1.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("=> Cmd+C to continue")
	wait()

	logrus.Println("moving on to m2 (an error is expected)")
	// Initialize the managers
	if err := m2.InitWithOptions(recoverAssets(), options2); err != nil {
		logrus.Fatal(err)
	}

	// Start m2
	if err := m2.Start(); err != nil {
		logrus.Error(err)
	}

	logrus.Println("=> Cmd+C to continue")
	wait()

	logrus.Println("moving on to m3 (an error is expected)")
	if err := m3.Init(recoverAssets()); err != nil {
		logrus.Fatal(err)
	}

	// Start m3
	if err := m3.Start(); err != nil {
		logrus.Error(err)
	}

	logrus.Println("updating activated probes of m3 (no error is expected)")

	mkdirID := manager.ProbeIdentificationPair{UID: "MyVFSMkdir2", EbpfFuncName: "kprobe_vfs_mkdir"}
	if err := m3.UpdateActivatedProbes([]manager.ProbesSelector{
		&manager.ProbeSelector{
			ProbeIdentificationPair: mkdirID,
		},
	}); err != nil {
		logrus.Error(err)
	}

	vfsOpenID := manager.ProbeIdentificationPair{EbpfFuncName: "kprobe_open"}
	vfsOpenProbe, ok := m3.GetProbe(vfsOpenID)
	if !ok {
		logrus.Fatal("Failed to find kprobe/vfs_opennnnnn")
	}

	if vfsOpenProbe.Enabled {
		logrus.Errorf("kprobe/vfs_opennnnnn should not be enabled")
	}
}

// wait - Waits until an interrupt or kill signal is sent
func wait() {
	logrus.Printf("run next testcase after %d second ", 3)
	time.Sleep(time.Second * 3)
	return
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}
