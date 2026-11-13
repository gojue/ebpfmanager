# 介绍
[![](https://godoc.org/github.com/gojue/ebpfmanager?status.svg)](https://godoc.org/github.com/gojue/ebpfmanager)


ebpfmanager参照datadog/ebpf/manager包的思想，基于cilium/ebpf实现的ebpf类库封装。

相比`cilium/ebpf`实现配置化，自动加载，更具备面向对象思想，且实现了`probe`颗粒的卡开启关闭功能。 相比`datadog/ebpf`，实现了依赖包方式加载`cilium/ebpf`
，而非fork方式，这点与其期望走的方向一致。本库直接依赖上游 `cilium/ebpf`。
>Work is underway to convert this library to wrap the upstream library, rather than forking.


# 依赖

* Go 1.26.0 或更新版本；构建和运行需要 Linux。
* [cilium/ebpf v0.22.0](https://github.com/cilium/ebpf/releases/tag/v0.22.0)
* [go-bindata](https://github.com/shuLhan/go-bindata/cmd/go-bindata)  用于生成ebpf字节码文件的go包，与`go:embed`类似。
```shell
go get -d github.com/shuLhan/go-bindata/cmd/go-bindata
```

# 说明
manager与probe是一对多关系。每个probe必须配置`Section`与`EbpfFuncName`两个属性。如果是`k(ret)probe`或`u(ret)probe`，则还需要配置`AttachToFuncName`属性。
```go
    // UID 可选自定义的唯一字符串
    UID string
    
    // Section elf字节码的Section名字，比如SEC("[section]"). 用于识别probe的类型[ku](ret)?probe/xdp/(raw_)?tracepoint/tc等
    // 早期datadog/ebpf类库用于manager的collectionSpec.Programs的索引。
    // 但cilium/ebpf v0.7.0中，不被返回作为programSpec map作为索引。索引改用MatchFuncName
    Section string
    
    // AttachToFuncName 被HOOK的syscall名字，忽略系统内核版本、CPU位数，比如 mkdirat 会被转换为__x64_sys_mkdirat、__ia32_sys_mkdirat等
    // Uprobe时，直接作为挂载的函数名。
    // 若不填写，则自动获取  Section 字段的最后一段作为挂载函数名   
    AttachToFuncName string
    
    // EbpfFuncName 表示字节码内内核态C函数的名字，取自字节码elf的符号表
    EbpfFuncName string
    
    // funcName 目标hook对象的函数名；私有属性，会自动计算赋值。uprobe中，若为空，则使用offset。
    funcName  string
```

# 上游同步与兼容性

本次手动同步的基线为 DataDog/ebpf-manager `main` 的
[`ecf203d78b8777fb7f61e77062a30eb7b1b70b3f`](https://github.com/DataDog/ebpf-manager/commit/ecf203d78b8777fb7f61e77062a30eb7b1b70b3f)
（2026-10-29）。上次同步为本库 `467114a3`，对应上游 `31843479`。
核心实现、内部辅助包和测试跟随上游；模块路径、定制示例、`kernel` 包和以下调用约定保留：

* `Probe` 的平铺字段 `UID`、`Section`、`EbpfFuncName`、`AttachToFuncName`、
  `Ifname`、`Ifindex`、`IfindexNetns`、`AttachPID`、`SkipLoopback` 和 `LinkPinPath`。
* `UAddress` 是调用方计算的 ELF 文件偏移；`UprobeOffset` 是相对偏移。
  `UAddress == 0` 时先解析符号，再叠加 `UprobeOffset`。
* `ConstantEditor` 自动识别 BTF 全局常量，无需 eCapture 增加
  `BTFGlobalConstant`；仍支持汇编常量和上游回调编辑器。
* `Options.RLimit`、`ExcludedEbpfFuncs`、`RingbufMaps`、`RingbufMapOptions`、
  `PerfMapStats`、`EditInnerMap` 和公开的 `Editor` 接口。
* `DumpMaps` 保留字符串返回值，流式接口名为 `DumpMapsTo`；
  `DetachHook` 保留两个字符串参数，新接口为 `DetachHookByID`。
  `NewMap` / `NewPerfRing` 保留值参数，指针接口为 `NewMapFromSpec` / `NewPerfRingFromSpec`。
* 默认保留程序指令，以兼容已有 `CloneProgram` 调用。
  `Options.DiscardProgramSpecs` 可启用上游的指令清理策略；需要克隆的探针仍应设置 `KeepProgramSpec`。

PMU / bpf_link 挂载不要求挂载 tracefs；显式选择 tracefs 的探针仍会在不可用时返回错误。

Map 替换使用 cilium 的独立 FD 引用；Manager 清理不会关闭调用方持有的原始 Map。
旧 `CleanExternal*` 常量保留，但 Map 的生命周期按 Manager 自己持有的引用管理。
`Map.Freeze` 字段只保留源码兼容性（cilium 已移除 `MapSpec.Freeze`）；需要冻结时，
请在加载后对 `*ebpf.Map` 显式调用 `Freeze()`。
上游 MIT 许可证保存在 `LICENSE.upstream`，本库原有 `LICENSE` 保留。

在具有 BPF 权限的 Linux 环境运行回归测试：

```sh
make -C testdata
go test -race -exec sudo ./...
```

示例的完整构建和运行检查入口为 `bash examples/test.sh`，会重新编译 eBPF、
生成 `probe.go`、编译 Go 并运行每个示例，需要 Linux 和免密 sudo。
每个示例默认超时 180 秒，可用 `EXAMPLE_TIMEOUT` 调整；任一构建或运行返回非零即失败。

CI 在每次 push 和 PR 更新时，通过独立的 `examples` job 执行该脚本。
在一次性 Linux 检出目录可用同一入口复现 CI 的环境隔离：

```sh
bash .github/scripts/test-examples.sh
```

该入口预先下载 Go 依赖，在私有网络、挂载和 PID 命名空间中运行，使用专用 `eth0`、
bpffs 和 `/tmp`，不会把 TC/XDP 探针挂到宿主机网卡。需预装 clang、LLVM、make、
bpftool、iproute2 和 Go。它是示例构建与运行的烟雾测试，不代替下游业务 E2E：
网络示例不检查 HTTP 成功，隔离环境中的外网请求会失败；LSM 示例在不支持时自行返回。
`tests_and_benchmarks` 的 `{ Input:42 Output:128 }` 是故意错误的演示输入，
其 `FAIL` 日志不代表脚本执行失败。

2026-11-13 的隔离验证使用 Linux arm64、内核 6.8 和 Go 1.26.0，
eCapture 源码基线为 `6396fc7259c1a427c8bc4c26d4f6c944a873bb39` 加当时的工作区改动。
只在验证副本中将模块依赖替换为本库，未修改 eCapture 调用代码：

* 本库带 race detector 的完整测试通过，包含真实 PMU / tracefs uprobe、
  pinned Map / Program / Link 复用、Map 引用生命周期和 ringbuf 停止并发回归。
* eCapture 的 `go test -race ./...`、生产构建标签下的 lint，以及
  `make clean && make core`、`make clean && make nocore`、`make clean && make all` 均通过。
* 最终二进制通过 TLS 严格 E2E 共 99 项：OpenSSL 26 项、GoTLS 52 项、GnuTLS 21 项，
  覆盖 text / keylog / pcapng、TC 抓包、HTTP/3 和网络输出；
  Bash、Zsh、MySQL 辅助探针回归另有 3 项通过。
* 本库 Linux amd64 / loong64 测试二进制交叉编译通过。
  此次未在这些架构、Android 或最低支持版本内核上进行运行时验证。

# 使用方法

参考`examples`目录下例子，比如`uprobe`

```go
package main

import (
	"github.com/gojue/ebpfmanager"
	"github.com/sirupsen/logrus"
)

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			Section:          "uprobe/readline",
			EbpfFuncName:     "uprobe_readline",
			AttachToFuncName: "readline",
			BinaryPath:       "/usr/bin/bash",
		},
	},
}

func main() {
	// Initialize the manager
	if err := m.Init(recoverAssets()); err != nil {
		logrus.Fatal(err)
	}

	// Start the manager
	if err := m.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	// Spawn a bash and right a command to trigger the probe
	if err := trigger(); err != nil {
		logrus.Error(err)
	}

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
}
```

# 案例项目

* eCapture : [capture SSL/TLS text content without CA cert using eBPF.](https://github.com/ehids/ecapture)
* eHIDS-Agent : [A Linux Host-based Intrusion Detection System based on eBPF.](https://github.com/ehids/ehids-agent)

# 注意

1. v0.7.0及以后的版本中，ebpf在`loadProgram`函数返回的progs map中，索引已经改为C代码中函数名。 见`elf_reader.go`312行`res[prog.Name] = prog`
   ，这点不同于老版本。（老版本是以section名字作为索引）
2. 在 [datadog/ebpf af587081](https://github.com/DataDog/ebpf/commit/af5870810f0b2c2f9ba996d02db16955de58266f)  Nov 17,
   2021 版本上实现本类库。

# 感谢

感谢 [https://jetbrains.com/](https://jetbrains.com/) 的 All Products Pack IDE使用授权。
