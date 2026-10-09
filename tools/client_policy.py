"""Client-only conformance checks. No import or dependency on the server repository."""

from __future__ import annotations

import json
import re
import stat
import tomllib
from pathlib import Path
from typing import Any, Iterable


SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
IDENTIFIER = re.compile(r"[a-z][a-z0-9-]{0,62}")
CANONICAL_PRODUCT_ID = re.compile(r"x[a-z]{3}")
CLIENT_LIMIT_KEYS = {"max_record_bytes", "max_spool_bytes", "max_spool_entries"}
EXPORTED_RUST_ABI = re.compile(
    r"#\[\s*(?:unsafe\s*\(\s*)?(?:no_mangle|export_name)\b"
    r'|\bpub(?:\([^)]*\))?\s+(?:unsafe\s+)?extern\s*"(?:C(?:-unwind)?|system)"\s+fn\b'
)


class ConformanceError(RuntimeError):
    """A manifest, source tree, or generated artifact violates platform policy."""


def _regular_file(path: Path) -> None:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ConformanceError(f"{path}: must be one regular, unlinked file")


def _toml(path: Path) -> dict[str, Any]:
    _regular_file(path)
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ConformanceError(f"{path}: invalid UTF-8 TOML: {error}") from error
    if not isinstance(value, dict):
        raise ConformanceError(f"{path}: expected a table")
    return value


def _json(path: Path) -> dict[str, Any]:
    _regular_file(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ConformanceError(f"{path}: invalid UTF-8 JSON: {error}") from error
    if not isinstance(value, dict):
        raise ConformanceError(f"{path}: expected an object")
    return value


def _exact_keys(value: dict[str, Any], allowed: set[str], required: set[str], context: str) -> None:
    unknown = set(value) - allowed
    missing = required - set(value)
    if unknown or missing:
        raise ConformanceError(
            f"{context}: keys differ: missing={sorted(missing)}, unknown={sorted(unknown)}"
        )


def _string_list(value: Any, context: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise ConformanceError(f"{context}: expected {'a non-empty' if not allow_empty else 'an'} array")
    if any(not isinstance(item, str) or IDENTIFIER.fullmatch(item) is None for item in value):
        raise ConformanceError(f"{context}: contains an invalid identifier")
    if len(value) != len(set(value)):
        raise ConformanceError(f"{context}: duplicate values are forbidden")
    return value


def load_profiles(foundation_root: Path) -> tuple[dict[str, dict[str, Any]], set[str]]:
    profile_root = foundation_root / "profiles"
    catalog = _toml(profile_root / "capabilities.toml")
    _exact_keys(catalog, {"format", "capabilities"}, {"format", "capabilities"}, "capability catalog")
    if catalog["format"] != 1 or not isinstance(catalog["capabilities"], dict):
        raise ConformanceError("capability catalog: unsupported format")
    capabilities = set(catalog["capabilities"])
    if not capabilities or any(IDENTIFIER.fullmatch(item) is None for item in capabilities):
        raise ConformanceError("capability catalog: invalid capability identifier")
    for identifier, value in catalog["capabilities"].items():
        if not isinstance(value, dict):
            raise ConformanceError(f"capability {identifier}: expected a table")
        _exact_keys(value, {"owner", "state"}, {"owner", "state"}, f"capability {identifier}")
        if value["owner"] not in {"foundation", "product-adapter"}:
            raise ConformanceError(f"capability {identifier}: invalid owner")
        if value["state"] not in {"current", "planned"}:
            raise ConformanceError(f"capability {identifier}: invalid state")

    profiles: dict[str, dict[str, Any]] = {}
    required_keys = {
        "format",
        "id",
        "kind",
        "formal_targets",
        "http_adapters",
        "web_profiles",
        "required_capabilities",
        "optional_capabilities",
    }
    for path in sorted(profile_root.glob("*.toml")):
        if path.name == "capabilities.toml":
            continue
        value = _toml(path)
        _exact_keys(value, required_keys | {"policy"}, required_keys, str(path))
        identifier = value["id"]
        if value["format"] != 1 or not isinstance(identifier, str) or IDENTIFIER.fullmatch(identifier) is None:
            raise ConformanceError(f"{path}: invalid profile identity")
        if path.stem != identifier or identifier in profiles:
            raise ConformanceError(f"{path}: profile filename/id mismatch or duplicate")
        if value["kind"] != "client":
            raise ConformanceError(f"{path}: invalid profile kind")
        for key in ("formal_targets", "http_adapters", "web_profiles"):
            items = value[key]
            if not isinstance(items, list) or any(not isinstance(item, str) or not item for item in items):
                raise ConformanceError(f"{path}.{key}: expected unique strings")
            if len(items) != len(set(items)):
                raise ConformanceError(f"{path}.{key}: duplicate values are forbidden")
        required = set(_string_list(value["required_capabilities"], f"{path}.required_capabilities"))
        optional = set(_string_list(value["optional_capabilities"], f"{path}.optional_capabilities"))
        if required & optional or not required | optional <= capabilities:
            raise ConformanceError(f"{path}: capability set is inconsistent with the catalog")
        if "bounded-spool" in required:
            policy = value.get("policy")
            if not isinstance(policy, dict) or not isinstance(policy.get("client_limits"), dict):
                raise ConformanceError(f"{path}: bounded-spool requires policy.client_limits")
            limits = policy["client_limits"]
            _exact_keys(limits, CLIENT_LIMIT_KEYS, CLIENT_LIMIT_KEYS, f"{path}.policy.client_limits")
            if any(type(limit) is not int or limit <= 0 for limit in limits.values()):
                raise ConformanceError(f"{path}: client limits must be positive integers")
            delivery = policy.get("delivery")
            keys = {"batch_records", "max_backoff_seconds", "max_jitter_percent", "max_queue_failures"}
            if not isinstance(delivery, dict):
                raise ConformanceError(f"{path}: bounded-spool requires policy.delivery")
            _exact_keys(delivery, keys, keys, f"{path}.policy.delivery")
            if any(type(limit) is not int or limit <= 0 for limit in delivery.values()):
                raise ConformanceError(f"{path}: delivery limits must be positive integers")
        profiles[identifier] = value
        if "mobile-ffi" in required:
            policy = value.get("policy")
            if not isinstance(policy, dict) or not isinstance(policy.get("ffi"), dict):
                raise ConformanceError(f"{path}: mobile-ffi requires policy.ffi")
            ffi = policy["ffi"]
            keys = {"abi_revision", "max_input_bytes", "max_output_bytes", "max_handles"}
            _exact_keys(ffi, keys, keys, f"{path}.policy.ffi")
            if any(type(limit) is not int or limit <= 0 for limit in ffi.values()):
                raise ConformanceError(f"{path}: FFI policy values must be positive integers")
    if set(profiles) != {"desktop-client", "mobile-client", "offline-maintenance"}:
        raise ConformanceError("profiles: first-generation profile set is incomplete")
    return profiles, capabilities


def load_product_manifest(product_root: Path) -> dict[str, Any]:
    return _toml(product_root / "xcsc-client.toml")


def verify_client_lock(path: Path, version: str, revision: str | None = None) -> int:
    """Inspect the resolved full graph, including renamed transitive packages."""
    lock = _toml(path)
    packages = lock.get("package")
    if not isinstance(packages, list) or any(not isinstance(package, dict) for package in packages):
        raise ConformanceError("[client-source-identity] Cargo.lock package graph is invalid")
    client_packages = 0
    for package in packages:
        name = package.get("name", "")
        source = str(package.get("source", ""))
        if name == "xcss" or name.startswith("xcss-") or "github.com/isarmg/xcss" in source:
            raise ConformanceError(f"[client-boundary] {path}: transitive server package {name}")
        if name.startswith("xcsc-"):
            raise ConformanceError(f"[client-source-identity] {path}: retired split client package {name}")
        if name == "xcsc":
            client_packages += 1
            expected = f"git+https://github.com/isarmg/xcsc.git?rev={revision}#{revision}"
            if package.get("version") != version or (revision is not None and source != expected):
                raise ConformanceError(f"[client-source-identity] {path}: resolved xcsc differs from manifest")
    if client_packages != 1:
        raise ConformanceError(f"[client-source-identity] {path}: expected exactly one resolved xcsc package")
    return len(packages)


def verify_manifest(product_root: Path, foundation_root: Path) -> dict[str, Any]:
    profiles, _ = load_profiles(foundation_root)
    manifest = load_product_manifest(product_root)
    _exact_keys(
        manifest,
        {"format", "product_id", "foundation", "components", "source_roots"},
        {"format", "product_id", "foundation", "components", "source_roots"},
        "product manifest",
    )
    product_id = manifest["product_id"]
    if manifest["format"] != 1 or not isinstance(product_id, str) or IDENTIFIER.fullmatch(product_id) is None:
        raise ConformanceError("product manifest: invalid format or product_id")
    if CANONICAL_PRODUCT_ID.fullmatch(product_id) is not None and not product_id.endswith("c"):
        raise ConformanceError("[client-role] canonical product_id must identify a Client with suffix c")
    foundation = manifest["foundation"]
    if not isinstance(foundation, dict):
        raise ConformanceError("product manifest.foundation: expected a table")
    _exact_keys(
        foundation,
        {"platform_generation", "version"},
        {"platform_generation", "version"},
        "product manifest.foundation",
    )
    if foundation["platform_generation"] != 1:
        raise ConformanceError("product manifest: unsupported platform generation")
    if not isinstance(foundation["version"], str) or SEMVER.fullmatch(foundation["version"]) is None:
        raise ConformanceError("product manifest: invalid xcsc version")
    source_roots(product_root, manifest)
    components = manifest["components"]
    if not isinstance(components, list) or not components:
        raise ConformanceError("product manifest: at least one component is required")
    component_ids: set[str] = set()
    for index, component in enumerate(components):
        context = f"product manifest.components[{index}]"
        if not isinstance(component, dict):
            raise ConformanceError(f"{context}: expected a table")
        _exact_keys(
            component,
            {"id", "profile", "http_adapter", "web_profile", "capabilities", "client_limits"},
            {"id", "profile", "capabilities"},
            context,
        )
        component_id = component["id"]
        profile_id = component["profile"]
        if not isinstance(component_id, str) or IDENTIFIER.fullmatch(component_id) is None:
            raise ConformanceError(f"{context}.id: invalid identifier")
        if component_id in component_ids:
            raise ConformanceError(f"{context}.id: duplicate component")
        component_ids.add(component_id)
        if not isinstance(profile_id, str) or profile_id not in profiles:
            raise ConformanceError(f"{context}.profile: unknown Profile {profile_id!r}")
        profile = profiles[profile_id]
        declared = set(_string_list(component["capabilities"], f"{context}.capabilities", allow_empty=False))
        required = set(profile["required_capabilities"])
        allowed = required | set(profile["optional_capabilities"])
        if not required <= declared:
            raise ConformanceError(f"{context}: missing required capabilities {sorted(required - declared)}")
        if not declared <= allowed:
            raise ConformanceError(f"{context}: capabilities are not allowed by Profile: {sorted(declared - allowed)}")
        if "bounded-spool" in declared:
            limits = component.get("client_limits")
            if not isinstance(limits, dict):
                raise ConformanceError(f"{context}: bounded-spool requires client_limits")
            _exact_keys(limits, CLIENT_LIMIT_KEYS, CLIENT_LIMIT_KEYS, f"{context}.client_limits")
            maximum = profile["policy"]["client_limits"]
            if any(type(limit) is not int or not 0 < limit <= maximum[key] for key, limit in limits.items()):
                raise ConformanceError(f"{context}: client_limits exceed the xcsc Profile")
        elif "client_limits" in component:
            raise ConformanceError(f"{context}: Profile does not accept client_limits")
        adapters = profile["http_adapters"]
        if adapters:
            if component.get("http_adapter") not in adapters:
                raise ConformanceError(f"{context}: http_adapter is not allowed by Profile")
        elif "http_adapter" in component:
            raise ConformanceError(f"{context}: Profile does not accept an http_adapter")
        web_profiles = profile["web_profiles"]
        if web_profiles:
            if component.get("web_profile") not in web_profiles:
                raise ConformanceError(f"{context}: web_profile is not allowed by Profile")
        elif "web_profile" in component:
            raise ConformanceError(f"{context}: Profile does not accept a web_profile")
    return manifest


def source_roots(product_root: Path, manifest: dict[str, Any]) -> list[Path]:
    values = manifest.get("source_roots")
    if not isinstance(values, list) or not values or any(not isinstance(x, str) or not x for x in values):
        raise ConformanceError("source_roots: expected non-empty relative paths")
    root = product_root.resolve(strict=True)
    paths = []
    for value in values:
        relative = Path(value)
        if relative.is_absolute() or ".." in relative.parts:
            raise ConformanceError("source_roots: path escapes product")
        path = root / relative
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(root) or not path.is_dir():
            raise ConformanceError("source_roots: invalid directory")
        paths.append(path)
    return paths


def verify_source(product_root: Path, foundation_root: Path) -> dict[str, Any]:
    import os

    # Source roots and owning-crate traversal must use one physical identity.
    # On macOS a lexical /var root otherwise never matches /private/var and
    # an unowned ABI source can walk to the filesystem root forever.
    product_root = product_root.resolve(strict=True)
    manifest = verify_manifest(product_root, foundation_root)
    patterns = []
    capabilities = {cap for component in manifest["components"] for cap in component["capabilities"]}
    if "bounded-spool" in capabilities:
        patterns.append(("client-runtime-ownership", re.compile(
            r"\bfn\s+(?:jitter|sampling_jitter|retry_jitter|exponential_backoff)\s*\("
            r"|\bSARMGSPOOL\b|\bspool\.instance\.lock\b"
            r"|\b(?:enum\s+(?:FlushOutcome|FailureDisposition|QuarantineReason|CredentialAuthorization|CredentialMutation)|struct\s+(?:RetryBackoff|DeliveryWorker|DeliveryTrigger|QueueFailureStreak|CredentialSnapshot|ClientIdentity|ClientSession|SingleInstanceLock)|trait\s+CredentialStore|fn\s+deliver_batch)\b"
            r"|\b[a-z_]*backoff\s*=\s*\([^;\n]*\*\s*2\b")))
    if "mobile-ffi" in capabilities:
        patterns.append(("mobile-ffi-ownership", re.compile(
            r"\b(?:struct\s+HandleRegistry|fn\s+(?:read_c_string|checked_c_string|guard_value)|LAST_ERROR)\b|@_silgen_name")))
    root_cargo = product_root / "Cargo.toml"
    workspace = _toml(root_cargo).get("workspace", {}).get("dependencies", {}) if root_cargo.is_file() else {}
    findings = []
    count = 0
    ignored = {".git", "node_modules", "target", "dist", "release", "build", ".gradle", "__pycache__"}
    mobile_abi_owners: dict[Path, bool] = {}

    def owns_mobile_abi(path: Path) -> bool:
        # An ordinary Rust business library may protect SQLite callbacks or
        # test deliberate panics. Only the exported ABI crate and its helper
        # modules must delegate panic translation to xcsc::mobile_ffi. Check
        # the complete owning crate, so moving a guard to a sibling module or
        # omitting that module from source_roots cannot hide an ABI owner.
        owner = path.parent
        while owner != product_root and not (owner / "Cargo.toml").is_file():
            owner = owner.parent
        cargo = owner / "Cargo.toml"
        if not cargo.is_file():
            return True  # An unowned source cannot establish a business scope.
        if owner in mobile_abi_owners:
            return mobile_abi_owners[owner]
        package = _toml(cargo)
        boundary = "package" not in package or bool(
            {"cdylib", "staticlib"} & set(package.get("lib", {}).get("crate-type", []))
        )
        for dependency, requirement in _walk_dependencies(package):
            if isinstance(requirement, dict) and requirement.get("workspace") is True:
                inherited = workspace.get(dependency, {})
                requirement = {**inherited, "features": sorted(set(inherited.get("features", [])) | set(requirement.get("features", [])))} if isinstance(inherited, dict) else inherited
            actual = requirement.get("package", dependency) if isinstance(requirement, dict) else dependency
            boundary = boundary or (
                actual == "xcsc" and isinstance(requirement, dict)
                and bool({"mobile-ffi", "jni"} & set(requirement.get("features", [])))
            )
        if not boundary:
            for directory, directories, files in os.walk(owner, followlinks=False):
                directories[:] = sorted(
                    name for name in directories
                    if name not in ignored
                    and not (Path(directory) / name).is_symlink()
                    and not (Path(directory) / name / "Cargo.toml").is_file()
                )
                if any(
                    name.endswith(".rs")
                    and not (Path(directory) / name).is_symlink()
                    and EXPORTED_RUST_ABI.search((Path(directory) / name).read_text(encoding="utf-8"))
                    for name in files
                ):
                    boundary = True
                    break
        mobile_abi_owners[owner] = boundary
        return boundary

    cargo_manifests: set[Path] = set()
    for root in source_roots(product_root, manifest):
        for directory, directories, files in os.walk(root, followlinks=False):
            for name in directories:
                path = Path(directory) / name
                if path.is_symlink():
                    raise ConformanceError(f"{path}: source symlinks are forbidden")
            directories[:] = sorted(name for name in directories if name not in ignored)
            for name in sorted(files):
                path = Path(directory) / name
                if path.is_symlink():
                    raise ConformanceError(f"{path}: source symlinks are forbidden")
                if path.suffix in {".rs", ".swift", ".kt", ".js", ".mjs", ".ts", ".tsx", ".html"}:
                    count += 1
                    source = path.read_text(encoding="utf-8")
                    if re.search(r"@xcss/(?:admin-web|admin-shell|admin-ui|http-client|contracts|design-tokens|web-fonts|web-toolchain)\b", source):
                        findings.append(f"[client-boundary] {path}: Server Web package in client UI")
                    for rule, pattern in patterns:
                        if pattern.search(source):
                            findings.append(f"[{rule}] {path}: product redefines client platform mechanics")
                    if (
                        "mobile-ffi" in capabilities
                        and path.suffix == ".rs"
                        and re.search(r"\bcatch_unwind\b", source)
                        and owns_mobile_abi(path)
                    ):
                        findings.append(f"[mobile-ffi-ownership] {path}: exported ABI panic translation belongs to xcsc")
                if name == "package.json":
                    package_json = _json(path)
                    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                        for dependency in package_json.get(section, {}):
                            if dependency.startswith("@xcss/") and not dependency.startswith("@xcss/client-"):
                                findings.append(f"[client-boundary] {path}: Server Web dependency {dependency}")
                if name != "Cargo.toml":
                    continue
                cargo_manifests.add(path.resolve())
    # Dependency ownership follows the actual product tree, not its advisory
    # source_roots list. In particular the workspace/package root manifest
    # cannot be excluded from this check.
    for directory, directories, files in os.walk(product_root, followlinks=False):
        directories[:] = sorted(name for name in directories if name not in ignored and not (Path(directory) / name).is_symlink())
        for name in files:
            if name == "Cargo.toml":
                cargo_manifests.add((Path(directory) / name).resolve())
    client_revision: str | None = None
    for path in sorted(cargo_manifests):
        for dependency, requirement in _walk_dependencies(_toml(path)):
            if isinstance(requirement, dict) and requirement.get("workspace") is True:
                requirement = workspace.get(dependency, {})
            package = requirement.get("package", dependency) if isinstance(requirement, dict) else dependency
            if package == "xcss" or package.startswith("xcss-"):
                findings.append(f"[client-boundary] {path}: server package {package}")
            if package.startswith("xcsc-"):
                findings.append(f"[client-source-identity] {path}: only the monolithic xcsc package may be consumed")
            if package == "xcsc":
                if not (
                    isinstance(requirement, dict)
                    and requirement.get("git") == "https://github.com/isarmg/xcsc.git"
                    and isinstance(requirement.get("rev"), str)
                    and re.fullmatch(r"[0-9a-f]{40}", requirement["rev"])
                    and requirement.get("version") == "=" + manifest["foundation"]["version"]
                    and "path" not in requirement
                ):
                    findings.append(f"[client-source-identity] {path}: {package} must pin the declared exact xcsc version and official source revision")
                elif client_revision is None:
                    client_revision = requirement["rev"]
                elif client_revision != requirement["rev"]:
                    findings.append(f"[client-source-identity] {path}: xcsc packages use different source revisions")
            if isinstance(requirement, dict):
                source = str(requirement.get("path", "")) + str(requirement.get("git", ""))
                if "xcss" in source:
                    findings.append(f"[client-boundary] {path}: server source dependency")
    lock_path = product_root / "Cargo.lock"
    if client_revision is not None:
        if not lock_path.exists():
            findings.append("[client-source-identity] pinned xcsc dependency requires a resolved Cargo.lock")
        else:
            verify_client_lock(lock_path, manifest["foundation"]["version"], client_revision)
    elif lock_path.exists():
        # Even a product without a direct xcsc import must not acquire xcss
        # transitively. Identity is checked when the locked xcsc is declared.
        for package in _toml(lock_path).get("package", []):
            name, source = package.get("name", ""), str(package.get("source", ""))
            if name == "xcss" or name.startswith("xcss-") or "github.com/isarmg/xcss" in source:
                findings.append(f"[client-boundary] {lock_path}: transitive server package {name}")
    if findings:
        raise ConformanceError("source verification failed:\n" + "\n".join(findings))
    return {"product": manifest["product_id"], "source_files": count, "status": "verified"}


def _walk_dependencies(value: Any, key: str = "") -> Iterable[tuple[str, Any]]:
    if not isinstance(value, dict):
        return
    if key in {"dependencies", "dev-dependencies", "build-dependencies"}:
        yield from value.items()
    elif key == "patch":
        for registry in value.values():
            if isinstance(registry, dict):
                yield from registry.items()
    elif key == "replace":
        for specification, requirement in value.items():
            yield specification.split(":", 1)[0], requirement
    for child, nested in value.items():
        if isinstance(nested, dict):
            yield from _walk_dependencies(nested, child)
