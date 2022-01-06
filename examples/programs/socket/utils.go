package main

import (
	"bytes"
	"fmt"
	"io"
	"syscall"

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

// trigger - Send a message through the socket pair to trigger the probe
func trigger(sockPair SocketPair) error {
	logrus.Println("Sending a message through the socket pair to trigger the probes ...")
	_, err := syscall.Write(sockPair[1], nil)
	if err != nil {
		return err
	}
	_, err = syscall.Read(sockPair[0], nil)
	return err
}

type SocketPair [2]int

func (p SocketPair) Close() error {
	err1 := syscall.Close(p[0])
	err2 := syscall.Close(p[1])

	if err1 != nil {
		return err1
	}
	return err2
}

// newSocketPair - Create a socket pair
func newSocketPair() (SocketPair, error) {
	return syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
}
