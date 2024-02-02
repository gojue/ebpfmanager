<hr>

# v0.4.5 (2024-02-02)
## What's Changed

**Full Changelog**: https://github.com/gojue/ebpfmanager/compare/v0.4.4...v0.4.5

<hr>

# v0.4.4 (2023-11-10)
## What's Changed
* add pinned map flag by @cfc4n in https://github.com/gojue/ebpfmanager/pull/34
* add ringbuf support by @spoock1024 in https://github.com/gojue/ebpfmanager/pull/35
* add kernel version detection to ringbuf map. by @cfc4n in https://github.com/gojue/ebpfmanager/pull/37

## New Contributors
* @spoock1024 made their first contribution in https://github.com/gojue/ebpfmanager/pull/35

**Full Changelog**: https://github.com/gojue/ebpfmanager/compare/v0.4.3...v0.4.4

<hr>

# v0.4.3 (2023-05-19)
* feat: support SockOps eBPF program.
**Full Changelog**: https://github.com/gojue/ebpfmanager/compare/v0.4.2...v0.4.3


<hr>

# v0.4.2 (2023-04-29)

## What's Changed
* fixes: concurrent map kallsymsCache. (#27) by @cfc4n in https://github.com/gojue/ebpfmanager/pull/28
* remove deprecated function by @cfc4n in https://github.com/gojue/ebpfmanager/pull/29
* Use /proc/kallsyms for kprobe/kretprobe function name search. (fixes #30) by @cfc4n in https://github.com/gojue/ebpfmanager/pull/31
* feat: supoort uprobe's opts address field. by @cfc4n in https://github.com/gojue/ebpfmanager/pull/32


**Full Changelog**: https://github.com/gojue/ebpfmanager/compare/v0.4.1...v0.4.2

<hr>

# v0.4.0 (2023-01-17)

- Update cilium/ebpf to v0.10.0 from v0.9.0 .
- sync datedog/ebpf-manager package feature. #26
- update golang version to 1.18.*
<hr>

# v0.3.0 (2022-06-15)

- Update cilium/ebpf to v0.9.0 from 0.8.1 .
- Add GitHub Actions (codeQL \ go-test)
-

fixed [#10 type 'Probe' contains 'sync.RWMutex' which is 'sync.Locker'](https://github.com/gojue/ebpfmanager/issues/10)

<hr>

# v0.2.3 (2022-04-09)

- Fix. [#1 GetSyscallFnNameWithSymFile memory leak](https://github.com/gojue/ebpfmanager/pull/2)
- Fix format type error.
