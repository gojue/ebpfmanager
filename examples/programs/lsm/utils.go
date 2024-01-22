package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
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

// trigger - Creates and then removes a tmp folder to trigger the probes
func trigger() error {
	logrus.Println("Generating events to trigger the probes ...")
	// Creating a tmp directory to trigger the probes
	tmpDir := "/tmp/test_folder"
	logrus.Printf("creating %v", tmpDir)
	err := os.MkdirAll(tmpDir, 0666)
	if err != nil {
		return err
	}

	// Removing a tmp directory to trigger the probes
	logrus.Printf("removing %v", tmpDir)
	return os.RemoveAll(tmpDir)
}

// Convert null-terminated int8 slice to byte slice
func int8SliceToByte(s []int8) []byte {
	var b []byte
	for _, v := range s {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}
	return b
}

// Convert null-terminated byte slice to Go string
func byteToString(b []byte) string {
	return string(b)
}

func checkSupportLSM() bool {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return false
	}

	release := byteToString(int8SliceToByte(uname.Release[:]))
	bootConfigPath := fmt.Sprintf("/boot/config-%s", release)
	file, err := os.Open(bootConfigPath)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// check CONFIG_BPF_LSM=y
		if strings.HasPrefix(line, "CONFIG_BPF_LSM=y") || strings.HasPrefix(line, "CONFIG_BPF_LSM=Y") {
			return true
		}
	}

	if err := scanner.Err(); err != nil {
		return false
	}

	return false
}
