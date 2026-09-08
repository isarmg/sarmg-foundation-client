#!/usr/bin/env bash
set -euo pipefail
cargo build --locked -p sarmg-client-fs-safety --example apple_sandbox
scratch="$(mktemp -d)"
scratch="$(cd "$scratch" && pwd -P)"
trap 'rm -rf -- "$scratch"' EXIT
mkdir -m 700 "$scratch/container"
cat > "$scratch/test.sb" <<EOF
(version 1)
(allow default)
(deny file-read* (literal "$scratch"))
EOF
sandbox-exec -f "$scratch/test.sb" target/debug/examples/apple_sandbox "$scratch/container"
