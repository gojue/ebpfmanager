<hr>

## v0.4.0 (2023-01-17)

- Update cilium/ebpf to v0.10.0 from v0.9.0 .
- sync datedog/ebpf-manager package feature. #26
- update golang version to 1.18.*
<hr>

## v0.3.0 (2022-06-15)

- Update cilium/ebpf to v0.9.0 from 0.8.1 .
- Add GitHub Actions (codeQL \ go-test)
-

fixed [#10 type 'Probe' contains 'sync.RWMutex' which is 'sync.Locker'](https://github.com/gojue/ebpfmanager/issues/10)

<hr>

## v0.2.3 (2022-04-09)

- Fix. [#1 GetSyscallFnNameWithSymFile memory leak](https://github.com/gojue/ebpfmanager/pull/2)
- Fix format type error.
