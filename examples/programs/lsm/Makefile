#
# Kernel Version detect
#

KERNEL_SUPPORT_LSM_FLAGS ?=
# 获取内核版本

KVER = $(shell uname -r)
KMAJ = $(shell echo $(KVER) | \
sed -e 's/^\([0-9][0-9]*\)\.[0-9][0-9]*\.[0-9][0-9]*.*/\1/')
KMIN = $(shell echo $(KVER) | \
sed -e 's/^[0-9][0-9]*\.\([0-9][0-9]*\)\.[0-9][0-9]*.*/\1/')
KREV = $(shell echo $(KVER) | \
sed -e 's/^[0-9][0-9]*\.[0-9][0-9]*\.\([0-9][0-9]*\).*/\1/')

kver_ge = $(shell \
echo test | awk '{if($(KMAJ) < $(1)) {print 0} else { \
if($(KMAJ) > $(1)) {print 1} else { \
if($(KMIN) < $(2)) {print 0} else { \
if($(KMIN) > $(2)) {print 1} else { \
if($(KREV) < $(3)) {print 0} else { print 1 } \
}}}}}' \
)

ARCH := $(shell uname -m)

ifeq ($(ARCH),aarch64)
	# arch aarch64
	ARCH_TARGET := arm64
else ifeq ($(ARCH),arm64)
	# arch arm64
	ARCH_TARGET := arm64
else
	# other arch
	ARCH_TARGET := other
endif

ifeq ($(ARCH_TARGET),arm64)
	ifeq ($(call kver_ge,6,0,0),1)
		KERNEL_SUPPORT_LSM_FLAGS = -DKERNEL_SUPPORT_LSM
	else
		# The arch arm64  kernel version is less than 6.0
	endif
else
	ifeq ($(call kver_ge,5,7,0),1)
		KERNEL_SUPPORT_LSM_FLAGS = -DKERNEL_SUPPORT_LSM
	else
		# The kernel version is less than 5.7
	endif
endif

all: build-ebpf build run

build-ebpf:
	mkdir -p ebpf/bin
	clang -D__KERNEL__ -D__ASM_SYSREG_H \
		$(KERNEL_SUPPORT_LSM_FLAGS) \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-I/lib/modules/$$(uname -r)/build/include \
		-I/lib/modules/$$(uname -r)/build/include/uapi \
		-I/lib/modules/$$(uname -r)/build/include/generated/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/generated \
		-O2 -emit-llvm \
		ebpf/main.c \
		-c -o - | llc -march=bpf -filetype=obj -o ebpf/bin/probe.o
	go run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg main -prefix "ebpf/bin" -o "probe.go" "ebpf/bin/probe.o"

build:
	go build -o bin/main .

run:
	sudo bin/main
