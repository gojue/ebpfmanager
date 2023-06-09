# 介绍
[![](https://godoc.org/github.com/gojue/ebpfmanager?status.svg)](https://godoc.org/github.com/gojue/ebpfmanager)

![HoneyGopher](./ehids-logo-1.png)

ebpfmanager参照datadog/ebpf/manager包的思想，基于cilium/ebpf实现的ebpf类库封装。

相比`cilium/ebpf`实现配置化，自动加载，更具备面向对象思想，且实现了`probe`颗粒的卡开启关闭功能。 相比`datadog/ebpf`，实现了依赖包方式加载`cilium/ebpf`
，而非fork方式，这点与其期望走的方向一致。且依赖`cilium/ebpf`版本更新到最新v0.9.0。
>Work is underway to convert this library to wrap the upstream library, rather than forking.


# 依赖

* [cilium/ebpf v0.9.0](https://github.com/cilium/ebpf/releases/tag/v0.9.0)    2022-06-16
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