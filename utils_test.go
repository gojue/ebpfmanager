package manager

import (
	"testing"
)

func TestGenerateEventName(t *testing.T) {
	probeType := "p"
	funcName := "func"
	UID := "UID"
	kprobeAttachPID := 1234

	eventName, err := GenerateEventName(probeType, funcName, UID, kprobeAttachPID)
	if err != nil {
		t.Error(err)
	}
	if len(eventName) > MaxEventNameLen {
		t.Errorf("Event name too long, kernel limit is %d : MaxEventNameLen", MaxEventNameLen)
	}

	// should be truncated
	funcName = "01234567890123456790123456789012345678901234567890123456789"
	eventName, err = GenerateEventName(probeType, funcName, UID, kprobeAttachPID)
	if (err != nil) || (len(eventName) != MaxEventNameLen) || (eventName != "p_01234567890123456790123456789012345678901234567890123_UID_1234") {
		t.Errorf("Should not failed and truncate the function name (len %d)", len(eventName))
	}

	UID = "12345678901234567890123456789012345678901234567890"
	_, err = GenerateEventName(probeType, funcName, UID, kprobeAttachPID)
	if err == nil {
		t.Errorf("Test should failed as event name length is too big for the kernel and free space for function Name is < %d", MinFunctionNameLen)
	}
}
