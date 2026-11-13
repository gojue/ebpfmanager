# Unreleased

* Manually synchronize the core implementation and regression fixtures with
  DataDog/ebpf-manager main at `ecf203d78b8777fb7f61e77062a30eb7b1b70b3f`
  (2026-10-29), following the previous `467114a3` / upstream `31843479` sync.
* Import upstream lifecycle and concurrency fixes, two-phase reader shutdown,
  TC/netns handling, attach-method fallback, tracing/iterator/perf-event support,
  map replacements, constant callbacks, exclusions, telemetry and BTF cleanup.
* Preserve the eCapture-facing API, automatic BTF constants, absolute `UAddress`
  plus relative `UprobeOffset`, legacy network/PID fields, link pinning, ringbuf
  callbacks, map editors and instruction patchers. No eCapture source migration
  is required by these interfaces.
* Keep the fork module path, Go 1.26.0 baseline, custom examples and kernel
  helpers. Retain upstream license attribution in `LICENSE.upstream`.
* Add compatibility regressions and run CI using the Go version in `go.mod`,
  generated test fixtures and the race detector. Example programs are compiled
  by `go test ./...`; interactive demos are not launched by CI.
* Validate unchanged eCapture callers on Linux arm64: race tests, production
  lint, clean CO-RE/non-CO-RE/combined builds, 99 TLS E2E cases and three auxiliary
  probe cases. See the README for the tested source revision and coverage limits.

<hr>

# v0.6.0 (2026-09-08)

## What's Changed

* Update compatibility with cilium/ebpf v0.22.0.
* Replace deprecated `CollectionSpec.RewriteConstants` and `RewriteMaps` usage with `VariableSpecs` and
  `MapReplacements` to match the current eBPF library API.
* Upgrade Go toolchain and core dependencies (`cilium/ebpf`, `florianl/go-tc`, `logrus`, `x/sys`, etc.) for current
  compatibility and maintenance.

**Full Changelog**: https://github.com/gojue/ebpfmanager/compare/v0.5.0...v0.6.0

<hr>

# v0.5.0 (2025-03-19)

## What's Changed

* support debugfs and tracefs by @cfc4n in https://github.com/gojue/ebpfmanager/pull/48
* Update dependencies by @cfc4n in https://github.com/gojue/ebpfmanager/pull/50

**Full Changelog**: https://github.com/gojue/ebpfmanager/compare/v0.4.6...v0.5.0

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
