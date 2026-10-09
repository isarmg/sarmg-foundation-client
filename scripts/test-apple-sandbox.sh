#!/usr/bin/env bash
set -euo pipefail
cargo build --locked -p xcsc --example apple_sandbox
target_dir="$(cargo metadata --locked --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
scratch="$(mktemp -d)"
scratch="$(cd "$scratch" && pwd -P)"
trap 'rm -rf -- "$scratch"' EXIT
mkdir -m 700 "$scratch/container"
cat > "$scratch/test.sb" <<EOF
(version 1)
(allow default)
(deny file-read* (literal "$scratch"))
EOF
sandbox-exec -f "$scratch/test.sb" "$target_dir/debug/examples/apple_sandbox" "$scratch/container"
