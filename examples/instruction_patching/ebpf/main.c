#include "include/bpf.h"
#include "include/bpf_map.h"
#include "include/bpf_helpers.h"

char _license[] SEC("license") = "GPL";


static void *(*bpf_patch)(unsigned long,...) = (void *)-1;

SEC("kprobe/security_socket_create")
int kprobe__security_socket_create(void *ctx) {
    int ret = 0;
    bpf_patch(ret);
    return 1;
}