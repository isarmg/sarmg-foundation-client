#!/usr/bin/env python3
"""Validate the independent client workspace and optional product sources."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from client_policy import ConformanceError, _toml, _walk_dependencies, load_profiles, verify_source

PACKAGES = {
    "sarmg-client-cli", "sarmg-client-runtime", "sarmg-mobile-ffi", "sarmg-client-fs-safety",
    "sarmg-client-secret", "sarmg-client-secret-envelope", "sarmg-client-error",
    "sarmg-secure-xml",
}


def check_dependencies(manifest: dict, directory: Path, workspace: dict) -> None:
    version = workspace["package"]["version"]
    for name, requirement in _walk_dependencies(manifest):
        source_directory = directory
        if isinstance(requirement, dict) and requirement.get("workspace") is True:
            requirement = workspace["dependencies"][name]
            source_directory = ROOT
        package = requirement.get("package", name) if isinstance(requirement, dict) else name
        if package.startswith("sarmg-") and package not in PACKAGES:
            raise ConformanceError(f"{directory}: dependency outside client platform: {package}")
        if isinstance(requirement, dict) and "path" in requirement:
            dependency = (source_directory / requirement["path"]).resolve(strict=True)
            expected = ROOT / "rust/crates" / package
            if package not in PACKAGES or dependency != expected or requirement.get("version") != f"={version}":
                raise ConformanceError(f"{directory}: dependency escapes client workspace or lacks exact version")


def check() -> dict:
    profiles, _ = load_profiles(ROOT)
    cargo = _toml(ROOT / "Cargo.toml")
    workspace = cargo["workspace"]
    members = {f"rust/crates/{name}" for name in PACKAGES}
    if set(workspace["members"]) != members:
        raise ConformanceError("workspace: client package set differs")
    if set(path.parent.name for path in (ROOT / "rust/crates").glob("*/Cargo.toml")) != PACKAGES:
        raise ConformanceError("workspace: unregistered crate")
    check_dependencies(cargo, ROOT, workspace)
    if workspace["package"]["repository"] != "https://github.com/isarmg/sarmg-foundation-client":
        raise ConformanceError("workspace: repository identity differs")
    for member in sorted(members):
        path = ROOT / member
        manifest = _toml(path / "Cargo.toml")
        if manifest["package"]["name"] != path.name:
            raise ConformanceError(f"{path}: package identity differs")
        if (path / "LICENSE").read_bytes() != (ROOT / "LICENSE").read_bytes():
            raise ConformanceError(f"{path}: license differs")
        check_dependencies(manifest, path, workspace)
    schema = json.loads((ROOT / "schemas/sarmg-client.schema.json").read_text())
    if set(schema["properties"]["components"]["items"]["properties"]["profile"]["enum"]) != set(profiles):
        raise ConformanceError("manifest schema Profile enum differs")
    return {"repository": ROOT.name, "packages": sorted(PACKAGES), "profiles": sorted(profiles)}


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
        print(f"sarmg-foundation-client: FAILED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
