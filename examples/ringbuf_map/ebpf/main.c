// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Andrii Nakryiko */
#include "include/bpf.h"
#include "include/bpf_map.h"
#include "include/bpf_helpers.h"


struct ringbuf_bpf_map_def SEC("maps/ringbuf_map") ringbuf_map = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 256*1024,
};


struct data_t {
    u32 pid;
    u32 flag;
};

SEC("kprobe/vfs_mkdir")
int kprobe_vfs_mkdir(void *ctx)
{
    bpf_printk("mkdir_ringbuf (vfs hook point)%u\n",bpf_get_current_pid_tgid());
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.flag = 1;
    bpf_ringbuf_output(&ringbuf_map,&data, sizeof(data), 0 /* flags */);
    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
