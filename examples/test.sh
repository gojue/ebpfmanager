#!/usr/bin/env bash
set -euo pipefail

# Resolve examples relative to this script, even when invoked from the repo root.
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ $(uname -s) != Linux ]]; then
    echo "Examples require Linux and BPF privileges." >&2
    exit 1
fi

count=0
while IFS= read -r -d '' makefile; do
    example=${makefile%/Makefile}
    printf '\n=== RUN %s ===\n' "$example"
    # Build eBPF, regenerate assets, build Go, then run the example. In
    # particular, do not hide a clang failure behind a successful llc process.
    timeout --kill-after=10s "${EXAMPLE_TIMEOUT:-180}s" \
        make -j1 -C "$example" SHELL=/bin/bash '.SHELLFLAGS=-e -o pipefail -c'
    printf '=== PASS %s ===\n' "$example"
    count=$((count + 1))
done < <(find . -name Makefile -type f -print0 | sort -z)

if (( count == 0 )); then
    echo "No example Makefiles found." >&2
    exit 1
fi
printf '\nAll %d examples completed successfully.\n' "$count"
