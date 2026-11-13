#include "common.h"

char __license[] __section("license") = "MIT";
const volatile unsigned long target_pid = 1;
const volatile unsigned long target_uid = 2;

struct {
    int (*type)[2];
    int (*max_entries)[1];
    unsigned int *key;
    unsigned long *value;
} hits __section(".maps");

__section("socket") int compat_constants(void *ctx) {
    return target_pid + target_uid;
}

__section("uprobe/compat") int compat_uprobe(void *ctx) {
    unsigned int key = 0;
    unsigned long *value = map_lookup_elem(&hits, &key);
    if (value) __sync_fetch_and_add(value, 1);
    return 0;
}
