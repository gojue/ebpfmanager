package manager

import (
	"bytes"
	"fmt"
	"testing"
)

func TestGetSyscallFnNameWithKallsyms(t *testing.T) {
	entries := []struct {
		fnName          string
		kallsymsContent string
		expected        string
	}{
		{
			fnName: "open",
			kallsymsContent: `
0000000000000000 T do_fchownat
0000000000000000 T __arm64_sys_fchownat
0000000000000000 T __arm64_sys_chown
0000000000000000 T __arm64_sys_lchown
0000000000000000 T vfs_fchown
0000000000000000 T ksys_fchown
0000000000000000 T __arm64_sys_fchown
0000000000000000 T vfs_open
0000000000000000 T build_open_how
0000000000000000 T build_open_flags
0000000000000000 t do_sys_openat2
0000000000000000 t __do_sys_openat2
0000000000000000 T __arm64_sys_openat2
0000000000000000 T __arm64_sys_creat
0000000000000000 T __arm64_compat_sys_open
0000000000000000 T __arm64_compat_sys_openat
0000000000000000 T __arm64_sys_open
0000000000000000 T __arm64_sys_openat
0000000000000000 T file_open_name
0000000000000000 T do_sys_open
0000000000000000 T vfs_setpos
0000000000000000 T generic_file_llseek_size
0000000000000000 T generic_file_llseek
0000000000000000 T fixed_size_llseek
0000000000000000 T no_seek_end_llseek
0000000000000000 T no_seek_end_llseek_size
0000000000000000 T noop_llseek
0000000000000000 T vfs_llseek
0000000000000000 T default_llseek
0000000000000000 t arch_local_irq_save
	`,
			expected: "__arm64_sys_open",
		},
		{
			fnName: "connect",
			kallsymsContent: `
0000000000000000 T __sys_connect
0000000000000000 T __arm64_sys_connect
	`,
			expected: "__arm64_sys_connect",
		},
		{
			fnName: "open",
			kallsymsContent: `
0000000000000000 T __SyS_open
0000000000000000 T __sys_open
	`,
			expected: "__SyS_open",
		},
	}

	for i, testEntry := range entries {
		t.Run(fmt.Sprintf("%s_%d", testEntry.fnName, i), func(t *testing.T) {
			res, err := getSyscallFnNameWithKallsyms(testEntry.fnName, bytes.NewBuffer([]byte(testEntry.kallsymsContent)), "arm64")
			if err != nil {
				t.Fatal(err)
			}

			if res != testEntry.expected {
				t.Errorf("expected %s, got %s", testEntry.expected, res)
			}
		})
	}
}
