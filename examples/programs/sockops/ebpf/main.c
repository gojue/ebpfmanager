#include "include/bpf.h"
#include "include/bpf_helpers.h"

SEC("sockops")
int bpf_sockops(struct bpf_sock_ops *skops)
{
	switch (skops->op) {
        default:
    		bpf_printk("eBPF sockops : %d \n",skops->op);
    	}
	return 0;
}
char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
