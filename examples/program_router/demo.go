package main

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/gojue/ebpfmanager"
)

func demoTailCall() error {
	logrus.Println("generating some traffic to show what happens when the tail call is not set up ...")
	trigger()
	time.Sleep(1 * time.Second)

	prog, _, err := m2.GetProgram(manager.ProbeIdentificationPair{EbpfFuncName: "classifier_three"})
	if err != nil {
		logrus.Fatal(err)
	}

	// prepare tail call
	routes := []manager.TailCallRoute{
		{
			ProgArrayName: "tc_prog_array",
			Key:           uint32(1),
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EbpfFuncName: "classifier_two",
			},
		},
		{
			ProgArrayName: "tc_prog_array",
			Key:           uint32(2),
			Program:       prog[0],
		},
	}

	// Map programs
	if err := m.UpdateTailCallRoutes(routes...); err != nil {
		return err
	}
	logrus.Println("generating some traffic to show what happens when the tail call is set up ...")
	trigger()
	return nil
}
