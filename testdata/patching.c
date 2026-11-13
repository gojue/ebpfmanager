#include "common.h"

char _license[] __section("license") = "MIT";

static void *(*bpf_patch_1)(unsigned long, ...) = (void *)-1;
static void *(*bpf_patch_2)(unsigned long, ...) = (void *)-2;

__section("socket")
int patching_test() {
	int ret = 0;
	bpf_patch_1(ret);
	bpf_patch_2(ret);
	return 1;
}
