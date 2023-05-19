package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
)

// recoverAssets - Recover ebpf asset
func recoverAssets() io.ReaderAt {
	buf, err := Asset("/probe.o")
	if err != nil {
		logrus.Fatal(errors.New(fmt.Sprintf("error:%v , couldn't find asset", err)))
	}
	return bytes.NewReader(buf)
}

// trigger - Generate some network traffic to trigger the probe
func trigger() {
	logrus.Println("Generating some network traffic to trigger the probes ...")
	_, _ = http.Get("https://www.bing.com/")
}
