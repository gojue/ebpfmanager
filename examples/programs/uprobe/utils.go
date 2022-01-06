package main

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"time"

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

// trigger - Spawn a bash and execute a command to trigger the probe
func trigger() error {
	logrus.Println("Spawning a shell and executing `id` to trigger the probe ...")
	cmd := exec.Command("/usr/bin/bash", "-i")
	stdinPipe, _ := cmd.StdinPipe()
	go func() {
		io.WriteString(stdinPipe, "id")
		time.Sleep(100*time.Millisecond)
		stdinPipe.Close()
	}()
	b, err := cmd.Output()
	if err != nil {
		return err
	}
	logrus.Printf("from bash: %v", string(b))
	return nil
}

