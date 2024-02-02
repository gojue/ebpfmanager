package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
)

// ByteOrder - host byte order
var ByteOrder binary.ByteOrder

const (
	//BpfProgShowProgramId = "bpftool prog show name %s |grep %s |awk -F ':' '{print $1}'"
	BpfProgShowProgramId = "prog show name %s |grep %s |awk -F ':' '{print $1}'"
	BpfProgDumpXlatedId  = "prog dump xlated id %s"
	BpfAsmCode           = "r1 = %d"
)

func init() {
	ByteOrder = getHostByteOrder()
}

// getHostByteOrder - Returns the host byte order
func getHostByteOrder() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}

// recoverAssets - Recover ebpf asset
func recoverAssets() io.ReaderAt {
	buf, err := Asset("/probe.o")
	if err != nil {
		logrus.Fatal(fmt.Errorf("error:%v, %s", err, "couldn't find asset"))
	}
	return bytes.NewReader(buf)
}

func check(progName string) error {
	if len(progName) >= 15 {
		progName = progName[:15]
	}
	var c = exec.Command("bpftool", "prog", "show", "name", progName)
	logrus.Println("executing command:", c.String())
	output, err := c.Output()
	if err != nil {
		return fmt.Errorf("executing command:%s, error:%v", c.String(), err)
	}
	outputStr := string(output)
	var outArrs = strings.Split(outputStr, ":")
	if len(outArrs) < 2 {
		return fmt.Errorf("failed to find prog id in output:%s", outputStr)
	}
	var progId = outArrs[0]
	logrus.Println("output:", progId)
	c = exec.Command("bpftool", "prog", "dump", "xlated", "id", progId)
	logrus.Println("executing command:", c.String())
	output, err = c.Output()
	if err != nil {
		return fmt.Errorf("executing command:%s, error:%v", c.String(), err)
	}
	outputStr = string(output)
	logrus.Printf("output:%s", outputStr)
	var asmCode = fmt.Sprintf(BpfAsmCode, eBPFAsmValue)
	if !strings.Contains(outputStr, asmCode) {
		logrus.Fatalf("failed to find asm code:%s in output:%s", asmCode, outputStr)
	}
	logrus.Println("found asm code:", asmCode)
	return nil
}

func wait() {
	logrus.Println("run next testcase after 3 second")
	time.Sleep(time.Second * 3)
	//return
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}
