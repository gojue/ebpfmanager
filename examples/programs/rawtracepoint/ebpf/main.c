#include "include/bpf.h"
#include "include/bpf_helpers.h"

SEC("raw_tracepoint/sys_enter")
int raw_tracepoint_sys_enter(void *ctx)
{
    bpf_printk("sys_enter enter (tracepoint)\n");
    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
