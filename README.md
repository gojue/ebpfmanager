# 介绍
参照datadog/ebpf/manager包的思想，基于cilium/ebpf实现的ebpf类库封装。
* cilium/ebpf v0.7.0   11 Oct 2021
* datadog/ebpf af5870810f0b2c2f9ba996d02db16955de58266f  Nov 17, 2021
# 依赖

```shell
go get -d github.com/shuLhan/go-bindata/cmd/go-bindata
```
# 说明
```go
    // UID 可选自定义的唯一字符串
    UID string
    
    // Section - elf字节码的Section名字，比如SEC("[section]"). 早期datadog/ebpf类库用于manager的collectionSpec.Programs的索引。
    // 但cilium/ebpf v0.7.0中，不被返回做诶programSpec map作为索引。 故，不能继续使用。
    // 索引改用MatchFuncName
    Section string
    
    // CopyProgram 是否为当前prob创建副本
    CopyProgram bool
    
    // SyscallFuncName 被HOOK的syscall名字，忽略系统内核版本、CPU位数，比如 mkdirat 会被转换为__x64_sys_mkdirat、__ia32_sys_mkdirat等
    // Uprobe时，直接作为挂载的函数名
	SyscallFuncName string
    
    // MatchFuncName 表示字节码内内核态C函数的名字
    MatchFuncName string

    // funcName 目标hook对象的函数名；uprobe中，若为空，则使用offset。
    funcName  string
```

# 注意
1. v0.7.0 版本的ebpf在`loadProgram`函数返回的progs map中，索引已经改为C代码中函数名。 见`elf_reader.go`312行`res[prog.Name] = prog`，这点不同于老版本。（老版本是以section名字作为索引）
2. 内核态代码编写时，函数命名必须以`[ku](ret)?probe_`开头，以便框架自动挂载