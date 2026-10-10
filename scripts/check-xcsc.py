#!/usr/bin/env python3
"""Validate the single client-only package and optional product sources."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from client_policy import ConformanceError, SEMVER, _toml, _walk_dependencies, load_profiles, verify_client_lock, verify_source

MODULES = {
    "cli", "runtime", "mobile_ffi", "fs_safety", "secret", "secret_envelope",
    "error", "secure_xml", "log", "contracts", "schema_identity", "state_file", "sqlite",
}


def check_dependencies(manifest: dict) -> None:
    for name, requirement in _walk_dependencies(manifest):
        package = requirement.get("package", name) if isinstance(requirement, dict) else name
        if package.startswith("xcsc-") or package == "xcsc":
            raise ConformanceError(f"dependency outside client platform: {package}")
        if isinstance(requirement, dict):
            if requirement.get("workspace") is True or "path" in requirement:
                raise ConformanceError("single client package forbids workspace or path dependencies")


def check() -> dict:
    profiles, _ = load_profiles(ROOT)
    cargo = _toml(ROOT / "Cargo.toml")
    if "workspace" in cargo or "package" not in cargo:
        raise ConformanceError("xcsc must be one root package, without a workspace facade")
    package = cargo["package"]
    if package.get("name") != "xcsc" or package.get("repository") != "https://github.com/isarmg/xcsc":
        raise ConformanceError("client package identity differs")
    if not isinstance(package.get("version"), str) or SEMVER.fullmatch(package["version"]) is None:
        raise ConformanceError("client package version is invalid")
    ignored = {".git", "target", "node_modules", "dist", "build", ".gradle", "__pycache__"}
    for directory, directories, files in os.walk(ROOT, followlinks=False):
        directories[:] = sorted(name for name in directories if name not in ignored)
        if any((Path(directory) / name).is_symlink() for name in directories):
            raise ConformanceError("client source directories must not be symlinks")
        if "Cargo.toml" in files and Path(directory) != ROOT:
            raise ConformanceError("client package contains an independent nested Cargo package")
    check_dependencies(cargo)
    locked_packages = verify_client_lock(ROOT / "Cargo.lock", package["version"])
    source = (ROOT / "src/lib.rs").read_text()
    for module in sorted(MODULES):
        if not (ROOT / "src" / module / "mod.rs").is_file() or f"pub mod {module};" not in source:
            raise ConformanceError(f"client module missing: {module}")
    if '#[cfg(not(any(target_os = "android", target_os = "ios")))]\npub mod cli;' not in source:
        raise ConformanceError("desktop service CLI must stay outside mobile targets")
    features = cargo.get("features", {})
    if "mobile-ffi" not in features or not {"mobile-ffi", "dep:jni"} <= set(features.get("jni", [])):
        raise ConformanceError("JNI must explicitly enable the guarded mobile FFI module")
    if not {"dep:sqlx", "dep:libsqlite3-sys"} <= set(features.get("offline-maintenance", [])):
        raise ConformanceError("offline-maintenance must explicitly enable its native SQLite dependencies")
    for module in ("sqlite", "state_file"):
        if f'#[cfg(all(target_os = "linux", feature = "offline-maintenance"))]\npub mod {module};' not in source:
            raise ConformanceError("offline maintenance must remain Linux feature-gated inside the client package")
    schema = json.loads((ROOT / "schemas/xcsc-client.schema.json").read_text())
    if set(schema["properties"]["components"]["items"]["properties"]["profile"]["enum"]) != set(profiles):
        raise ConformanceError("manifest schema Profile enum differs")
    return {"repository": ROOT.name, "packages": ["xcsc"], "modules": sorted(MODULES), "profiles": sorted(profiles), "locked_packages": locked_packages}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--product-root", type=Path)
    args = parser.parse_args()
    try:
        result = check()
        if args.product_root is not None:
            result["consumer"] = verify_source(args.product_root.resolve(strict=True), ROOT)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, ConformanceError) as error:
        print(f"xcsc: FAILED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
