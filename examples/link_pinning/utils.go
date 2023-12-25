package main

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"

	"errors"

	"github.com/sirupsen/logrus"
)

// recoverAssets - Recover ebpf asset
func recoverAssets() io.ReaderAt {
	buf, err := Asset("/probe.o")
	if err != nil {
		logrus.Fatal(errors.New(fmt.Sprintf("error:%v , couldn't find asset", err)))
	}
	return bytes.NewReader(buf)
}

// trigger - execute whoami to trigger the probes
func trigger() error {
	logrus.Println("Generating events to trigger the probes ...")
	// Run whoami to trigger the event
	cmd := exec.Command("/usr/bin/whoami")
	return cmd.Run()
}
