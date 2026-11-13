# ebpfmanager

[![Go Reference](https://pkg.go.dev/badge/github.com/gojue/ebpfmanager.svg)](https://pkg.go.dev/github.com/gojue/ebpfmanager)
[![Go-test](https://github.com/gojue/ebpfmanager/actions/workflows/go.yml/badge.svg?branch=master)](https://github.com/gojue/ebpfmanager/actions/workflows/go.yml)

ebpfmanager 是面向 Linux 的 Go eBPF 管理库，fork 自 [DataDog/ebpf-manager](https://github.com/DataDog/ebpf-manager)，并针对 [eCapture](https://github.com/gojue/ecapture) 等调用方保留定制接口。本库直接依赖 [cilium/ebpf](https://github.com/cilium/ebpf)，提供 eBPF 程序加载、探针挂载、Map 管理和事件读取的配置化封装。

主要能力包括：

- 管理 kprobe/kretprobe、uprobe/uretprobe、tracepoint、raw tracepoint、TC、XDP、cgroup、socket、LSM、tracing 和 perf event 等探针。
- 读取 perf buffer、ring buffer 事件，管理启动、停止和资源清理。
- 编辑常量、指令和 Map 规格，替换 Map，配置程序路由、克隆程序和动态增删 hook。
- 按选择器启用探针，并支持 Map、Program 和 Link pinning。

具体探针的可用性取决于 Linux 内核版本、内核配置、目标程序和运行权限。

## 依赖与安装

| 用途 | 要求 |
| --- | --- |
| Go 开发 | Go 1.26.0 或更新版本；完整依赖以 [go.mod](go.mod) 为准 |
| eBPF 加载 | 当前依赖 `github.com/cilium/ebpf v0.22.0`；运行需要 Linux 及相应 BPF 权限 |
| 编译示例和测试资产 | clang、LLVM、make、C 编译器及 Linux 开发头文件；示例检查还使用 bpftool、iproute2、util-linux 和免密 sudo |
| 示例资产生成 | Makefile 通过 `go run` 调用 go.mod 中的 go-bindata，无需额外执行 `go get -d` 或全局安装 |

在应用的 Go module 中安装 `v0.7.0`：

```sh
go get github.com/gojue/ebpfmanager@v0.7.0
```

导入路径仍为 `github.com/gojue/ebpfmanager`，包名为 `manager`。

加载 eBPF 时建议先在具备 sudo 权限的 Linux 环境验证。bpffs 用于 pinning；不使用 pinning 的普通加载并不因此要求挂载 bpffs。tracepoint 和 tracefs 挂载路径需要可用的 tracefs；kprobe/uprobe 的 PMU 或 bpf_link 路径不普遍依赖 tracefs。挂载方式、符号查找和回退路径的具体要求应按实际探针配置判断。

## 快速开始

仓库中的示例包含 C 程序、Go 调用代码和 Makefile。例如，在 Linux 检出目录运行：

```sh
go mod download
make -C examples/programs/tracepoint
```

该命令会编译 eBPF、重新生成 `probe.go`、构建并以 sudo 运行示例。建议在一次性检出目录运行，避免覆盖正在编辑的生成文件。

### Probe 配置

一个 `Manager` 可以管理多个 `Probe`。不要混淆 eBPF 函数名、ELF section 和被挂载的目标函数：

| 字段 | 含义 |
| --- | --- |
| `EbpfFuncName` | eBPF C 函数名，用于查找 ELF 中的程序，例如 `tracepoint_sys_enter_mkdirat`；不是 section 名 |
| `UID` | 可选标识，与 `EbpfFuncName` 共同组成 `ProbeIdentificationPair`，用于区分探针 |
| `Section` | 可选覆盖 ELF 程序的 section；未设置时使用 ELF 中的 section |
| `AttachToFuncName` | 本 fork 保留的目标函数配置；kprobe 路径会尝试解析 syscall 前缀，uprobe 路径用于符号定位；不是所有探针的必填项 |
| `HookFuncName` / `SyscallFuncName` / `MatchFuncName` | 分别用于精确目标符号、syscall 名或匹配模式；`HookFuncName` 优先，详见 [probe.go](probe.go) |
| `BinaryPath` | uprobe/uretprobe 对应的用户态 ELF 路径 |
| `UAddress` / `UprobeOffset` | 调用方提供的 ELF 文件偏移，以及在其基础上增加的相对偏移；`UAddress == 0` 时先解析符号 |

`UAddress` 不是进程运行时虚拟地址，也不是未经换算的 ELF 虚拟地址。`MatchFuncName` 用来定位目标函数，不是 eBPF 程序表的索引。完整配置与兼容字段见 [probe.go](probe.go) 和 [compat.go](compat.go)。

### 在应用中加载对象文件

将以下代码保存为应用目录中的 `main.go`。它加载上述 tracepoint 示例产生的 `probe.o`，等待退出信号后清理探针：

```go
package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	manager "github.com/gojue/ebpfmanager"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: tracepoint-demo /path/to/probe.o")
	}
	if err := run(os.Args[1]); err != nil {
		log.Fatal(err)
	}
}

func run(objectPath string) (err error) {
	object, err := os.Open(objectPath)
	if err != nil {
		return err
	}
	defer object.Close()

	m := &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:      "tracepoint/syscalls/sys_enter_mkdirat",
				EbpfFuncName: "tracepoint_sys_enter_mkdirat",
			},
		},
	}
	if err = m.InitWithOptions(object, manager.Options{RemoveRlimit: true}); err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, m.Stop(manager.CleanAll))
	}()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err = m.Start(); err != nil {
		return err
	}
	log.Print("probe attached; press Ctrl+C to stop")
	<-ctx.Done()
	return nil
}
```

在应用目录中构建并运行，将路径替换为实际生成的对象文件：

```sh
go build -o tracepoint-demo .
sudo ./tracepoint-demo /path/to/ebpfmanager/examples/programs/tracepoint/ebpf/bin/probe.o
```

本例的 C 程序通过 `bpf_printk` 输出到 tracefs 的 `trace_pipe`，Go 程序负责加载和生命周期管理。加载器接收 `io.ReaderAt`；除文件外，也可以使用 `bytes.NewReader` 加载嵌入的 eBPF 字节码。更多示例：

| 场景 | 示例目录 |
| --- | --- |
| 各种探针类型 | [examples/programs](examples/programs) |
| 探针选择器 | [activated_probes](examples/activated_probes) |
| 指令修改、Map 规格编辑 | [instruction_patching](examples/instruction_patching)、[mapspec_editor](examples/mapspec_editor) |
| 克隆程序与新增 hook | [clone_vs_add_hook](examples/clone_vs_add_hook) |
| Map 替换与路由、程序路由 | [map_rewrite_vs_map_router](examples/map_rewrite_vs_map_router)、[program_router](examples/program_router) |
| 对象及 Link pinning | [object_pinning](examples/object_pinning)、[link_pinning](examples/link_pinning) |
| Ring buffer、程序测试与基准 | [ringbuf_map](examples/ringbuf_map)、[tests_and_benchmarks](examples/tests_and_benchmarks) |

## 上游同步与兼容性

`v0.7.0` 包含 [PR #51](https://github.com/gojue/ebpfmanager/pull/51) 的上游同步，该 PR 于 2026-11-14 合入 master，合并提交为 [`6f15756`](https://github.com/gojue/ebpfmanager/commit/6f15756b340352535bded72e5e18f5ad2ce693aa)。同步基线为 DataDog/ebpf-manager main 的 [`ecf203d`](https://github.com/DataDog/ebpf-manager/commit/ecf203d78b8777fb7f61e77062a30eb7b1b70b3f)。这是明确的同步快照，不表示持续自动跟随上游最新提交。前一次同步为本库 `467114a3`，对应上游 `31843479`。

核心实现、内部辅助包和测试跟随上游；模块路径、定制示例、`kernel` 包及下列调用约定保留，以兼容现有 eCapture 调用：

- `Probe` 的平铺字段，以及 `AttachToFuncName`、`UAddress`、`AttachPID`、`Ifname`、`Ifindex`、`IfindexNetns`、`SkipLoopback`、`LinkPinPath` 等 fork 接口。
- `ConstantEditor` 对符合条件的 BTF 全局常量自动选择编辑方式；保留汇编常量和回调编辑器。汇编常量值需要 `uint64`，具体条件见 [constant_editor.go](constant_editor.go)。
- `Options.RLimit`、`ExcludedEbpfFuncs`、`RingbufMaps`、`RingbufMapOptions`、`PerfMapStats`、`EditInnerMap` 和公开的 `Editor` 接口。
- `DumpMaps` 保留字符串返回值，流式接口为 `DumpMapsTo`；`DetachHook` 保留两个字符串参数，另提供 `DetachHookByID`。
- `NewMap` / `NewPerfRing` 保留值参数，指针参数接口为 `NewMapFromSpec` / `NewPerfRingFromSpec`。
- 默认保留程序指令，以兼容 `CloneProgram`。若启用 `Options.DiscardProgramSpecs`，需要克隆的探针应设置 `KeepProgramSpec`；没有关联 Probe 的程序还需考虑 `KeepUnmappedProgramSpecs`。

Map 替换使用 cilium 的独立 FD 引用，Manager 清理不会关闭调用方持有的原始 Map。旧 `CleanExternal*` 常量仍保留，清理以 Manager 持有的引用为准。`MapOptions.Freeze` 字段仅保留源码兼容性；需要冻结 Map 时，请对已加载的 `*ebpf.Map` 显式调用 `Freeze()`。

## 测试与 CI

### 库回归测试

在具有 BPF 权限和编译工具的 Linux 环境运行：

```sh
go mod download
C_INCLUDE_PATH="/usr/include/$(gcc -dumpmachine)${C_INCLUDE_PATH:+:$C_INCLUDE_PATH}" make -C testdata
go test -count=1 -race -exec 'sudo -n' ./...
```

涉及 pinning 的测试要求 bpffs；环境不满足时会明确跳过，跳过不等于该能力已验证。架构或工具链不支持 race detector 时，可运行不带 `-race` 的测试，但应单独说明验证范围。

### 示例构建与运行

```sh
bash examples/test.sh
```

该脚本依次执行当前 20 个示例的 Makefile：编译 eBPF、生成 `probe.go`、构建 Go 程序并运行。每个示例默认超时 180 秒，可通过 `EXAMPLE_TIMEOUT` 调整；构建、运行或超时返回非零时，脚本立即失败。

推荐在一次性 Linux 检出目录使用与 CI 相同的隔离入口：

```sh
bash .github/scripts/test-examples.sh
```

该入口先下载 Go 依赖，再在私有网络、挂载和 PID 命名空间中运行，使用专用 `eth0`、bpffs 和 `/tmp`，不会把 TC/XDP 探针挂到宿主机网卡。它不提供独立内核：kprobe、tracepoint 和 LSM 等仍作用于当前 Linux 内核。

示例检查是构建与运行的烟雾测试，不等同于完整业务断言：网络示例不检查 HTTP 成功，隔离环境中的外网请求会失败；LSM 示例在不支持时自行返回；`tests_and_benchmarks` 的 `{ Input:42 Output:128 }` 是故意错误的演示输入，会打印 `FAIL`，但不代表脚本执行失败。

### GitHub Actions

[Go-test 工作流](.github/workflows/go.yml) 在所有分支的 push、PR 更新及手动触发时运行：

| Job | 检查内容 |
| --- | --- |
| `build` | 根据 go.mod 设置 Go，构建测试资产，执行 `go test -race -exec sudo ./...` |
| `examples` | 安装编译工具和可执行的 bpftool，通过隔离入口构建并运行全部示例 |

PR #51 最终提交的 [PR 检查](https://github.com/gojue/ebpfmanager/actions/runs/43461669643) 和 [push 检查](https://github.com/gojue/ebpfmanager/actions/runs/43461658205) 均通过；[合并提交的 Go-test](https://github.com/gojue/ebpfmanager/actions/runs/43462688521) 也已通过。本仓库的 CI 不会自动执行 eCapture 的完整构建和 E2E。

## eCapture 兼容性验证记录

2026-11-13 在 Linux ARM64 VM 和 LoongArch64 主机的隔离目录进行了下游验证。eCapture 基线为 `6cac65fe2b60c2bbf3b27b3451d7611e28e88c30`，manager 基线为 PR 开发阶段的 `84822043e8e6696d9c5480f080e6de4c67814acc`，并使用 `v0.6.0` 对照。只调整隔离副本中的库依赖，未修改 eCapture 调用代码。

两平台完成了 CO-RE、非 CO-RE、组合版的干净构建和启动检查，以及本库测试、eCapture 测试和生产标签 lint。下游 E2E 范围共 114 项：OpenSSL 27、GoTLS 52、GnuTLS 21、Bash/Zsh 3、CLI 11；不包含 Mysqld 和 PostgreSQL。

| 环境 | 组合版（该环境使用 CO-RE） | 非 CO-RE |
| --- | ---: | ---: |
| Linux ARM64 VM | 114/114 | 114/114 |
| Linux LoongArch64 主机 | 104/114 | 103/114 |

需要保留的结论边界：

- 龙芯的 10 项 GnuTLS 失败在旧 manager 上也可复现。已确认 Debian `3.8.9-3+deb13u4` 包回移补丁，使私有结构中 TLS 1.3 密钥偏移增加 264 字节；这不是本次 manager 升级或 bpffs 引起的问题。仅修改隔离 eCapture 副本的偏移后，CO-RE 和非 CO-RE 的 GnuTLS 21/21 均通过；该诊断补丁不属于 PR #51，不能据此将原版完整 E2E 改记为全部通过。
- 龙芯非 CO-RE 另有一项 OpenSSL 进程参数元数据断言失败，旧 manager 同样可复现。构建头文件与运行内核不同，结果不能推广为跨内核普遍兼容。
- GoTLS 首轮出现过一次 WebSocket 事件缺失，旧版与 PR 各重复 10 次通过，完整套件复测通过；表中结果包含复测，不代表最初一次运行全部成功。
- 龙芯两项 pinning 回归因环境无法挂载 bpffs 而跳过；它们不属于上述 114 项，也没有阻止 GnuTLS E2E 执行。ARM64 对应 pinning 测试通过。
- 这轮下游全量验证早于最终提交中的依赖更新及提交压缩，未在合并提交上重新执行。最终依赖版本已通过本库 CI 和 ARM64 的 20 个示例；不能将这些结果等同于重新跑过 eCapture 全量 E2E。

本轮没有要求 eCapture 修改调用接口；Android、所有最低内核版本及所有发行版 TLS 库布局不在此次完整验证范围内。

## 使用项目

- [eCapture](https://github.com/gojue/ecapture)：基于 eBPF 的 TLS 明文与密钥捕获工具。
- [eHIDS-Agent](https://github.com/gojue/ehids-agent)：基于 eBPF 的主机入侵检测 Agent。

## 许可证与致谢

本仓库许可证见 [LICENSE](LICENSE)（Apache-2.0）；导入的 DataDog 代码保留 [LICENSE.upstream](LICENSE.upstream) 中的 MIT 许可证声明。其他文件已有的版权和许可证声明应一并保留。

感谢 [JetBrains](https://www.jetbrains.com/) 提供 All Products Pack IDE 使用授权。
