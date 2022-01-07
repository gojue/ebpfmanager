package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/sirupsen/logrus"
)

// recoverAssets - Recover ebpf asset
func recoverAssets() io.ReaderAt {
	buf, err := Asset("/probe.o")
	if err != nil {
		logrus.Fatal(fmt.Errorf("error:%v, %s", err, "couldn't find asset"))
	}
	return bytes.NewReader(buf)
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
