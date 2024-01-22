#include "include/bpf.h"
#include "include/bpf_helpers.h"

#ifdef KERNEL_SUPPORT_LSM
    struct path;
    SEC("lsm/path_mkdir")
    int lsm_path_mkdir(const struct path *path)
    {
        bpf_printk("path_mkdir (LSM hook point)\n");
        return 0;
    };
#endif

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;