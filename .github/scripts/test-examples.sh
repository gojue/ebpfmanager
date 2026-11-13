#!/usr/bin/env bash
set -euo pipefail

# Run on a disposable Linux checkout: the examples regenerate probe.go assets.
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
if [[ $(uname -s) != Linux ]]; then
    echo "Examples require Linux." >&2
    exit 1
fi

sudo -n true
sudo -n bpftool version
go mod download

# Use the selected Go toolchain and predownloaded modules without network
# access. The PID namespace removes child processes on failure/cancellation.
sudo -n env "PATH=$PATH" "GOMODCACHE=$(go env GOMODCACHE)" \
    "GOCACHE=$(go env GOCACHE)" "GOTOOLCHAIN=local" "GOFLAGS=-mod=readonly" \
    unshare --mount --net --pid --fork --kill-child bash -s <<'ISOLATED'
set -euo pipefail
mount --make-rprivate /
mount -t tmpfs -o mode=1777 tmpfs /tmp
mount -t bpf bpf /sys/fs/bpf

# TC expects eth0 and XDP expects ifindex 2. Neither attaches to the host's
# interface. The examples don't assert HTTP success; external requests fail
# immediately in this namespace, which has no default route.
ip link set lo up
ip link add eth0 type dummy
ip link set eth0 up
test "$(ip -o link show eth0 | cut -d: -f1)" = 2
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
bash examples/test.sh
ISOLATED
