package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"errors"
	"github.com/sirupsen/logrus"
)

// recoverAssets - Recover ebpf asset
func recoverAssets(probe string) io.ReaderAt {
	buf, err := Asset(probe)
	if err != nil {
		logrus.Fatal(errors.New(fmt.Sprintf("error:%v , couldn't find asset", err)))
	}
	return bytes.NewReader(buf)
}

// trigger - Generate some network traffic to trigger the probe
func trigger() {
	_, _ = http.Get("https://www.google.com/")
}
